package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"restore/pkg/restore"
)

type options struct {
	metaPath   string
	sourceDir  string
	numWorkers int
}

// hardlinkTracker keeps track of inodes we've already processed
type hardlinkTracker struct {
	sync.Mutex
	seen map[uint64]bool
}

func newHardlinkTracker() *hardlinkTracker {
	return &hardlinkTracker{
		seen: make(map[uint64]bool),
	}
}

func (h *hardlinkTracker) isNewInode(ino uint64, nlink bool) bool {
	if !nlink {
		return true
	}

	h.Lock()
	defer h.Unlock()

	if _, exists := h.seen[ino]; exists {
		return false
	}

	h.seen[ino] = true
	return true
}

// getFileInfo extracts file information from os.FileInfo
func getFileInfo(info os.FileInfo) restore.FileInfo {
	stat := info.Sys().(*syscall.Stat_t)

	// Use target inode number if specified, otherwise use actual inode number
	ino := uint64(stat.Ino)

	return restore.FileInfo{
		Ino:       ino,
		Mode:      uint32(stat.Mode),
		Uid:       uint32(stat.Uid),
		Gid:       uint32(stat.Gid),
		Size:      uint64(stat.Size),
		Rdev:      uint64(stat.Rdev),
		AtimeSec:  stat.Atim.Sec,
		AtimeNsec: stat.Atim.Nsec,
		MtimeSec:  stat.Mtim.Sec,
		MtimeNsec: stat.Mtim.Nsec,
		CtimeSec:  stat.Ctim.Sec,
		CtimeNsec: stat.Ctim.Nsec,
		IsDir:     info.IsDir(),
		IsRegular: stat.Mode&syscall.S_IFMT == syscall.S_IFREG,
	}
}

// getXAttrs gets extended attributes for a file/directory
func getXAttrs(path string) ([]restore.XAttr, error) {
	size, err := syscall.Listxattr(path, nil)
	if err != nil || size == 0 {
		return nil, err
	}

	buf := make([]byte, size)
	size, err = syscall.Listxattr(path, buf)
	if err != nil {
		return nil, err
	}

	var xattrs []restore.XAttr
	start := 0
	for i := 0; i < size; i++ {
		if buf[i] == 0 {
			name := string(buf[start:i])
			value, err := syscall.Getxattr(path, name, nil)
			if err != nil {
				continue
			}

			valueBuf := make([]byte, value)
			_, err = syscall.Getxattr(path, name, valueBuf)
			if err != nil {
				continue
			}

			xattrs = append(xattrs, restore.XAttr{
				Name:  name,
				Value: valueBuf,
			})
			start = i + 1
		}
	}

	return xattrs, nil
}

func restorePath(writer *restore.WorkerWriter, hlTracker *hardlinkTracker, path string, parentIno uint64) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("failed to read directory: %v", err)
	}
	log.Printf("Restoring path: %s", path)
	var subdirs int
	var nameBytes int

	for pos, entry := range entries {
		if entry.Name() == "." || entry.Name() == ".." {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("failed to get entry info: %v", err)
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("failed to get stat_t")
		}
		nameBytes += len(entry.Name())
		fullPath := filepath.Join(path, entry.Name())

		// Recurse into directories
		if info.IsDir() {
			subdirs++

			if err := restorePath(writer, hlTracker, fullPath, uint64(stat.Ino)); err != nil {
				return err
			}

		}

		err = writer.CreateEntry(parentIno, uint64(pos), uint64(stat.Ino), uint32(info.Mode()), entry.Name())
		if err != nil {
			return fmt.Errorf("failed to create entry: %v", err)
		}

		// Handle inode
		isHardlink := stat.Nlink > 1
		if !info.IsDir() && hlTracker.isNewInode(uint64(stat.Ino), isHardlink) {
			fileInfo := getFileInfo(info)
			err = writer.CreateInode(fileInfo)
			if err != nil {
				return fmt.Errorf("failed to create inode: %v", err)
			}

			// Handle xattrs
			xattrs, err := getXAttrs(fullPath)
			if err == nil {
				for pos, xattr := range xattrs {
					err = writer.CreateXAttr(uint64(stat.Ino), uint64(pos), xattr)
					if err != nil {
						return fmt.Errorf("failed to create xattr: %v", err)
					}
				}
			}
		}
	}
	// Get directory info
	dirInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat directory: %v", err)
	}

	// Create directory inode
	dirFileInfo := getFileInfo(dirInfo)
	dirFileInfo.NrSubdirs = uint64(subdirs)
	dirFileInfo.NameBytes = uint64(nameBytes)

	return writer.CreateInode(dirFileInfo)
}

func main() {
	opts := options{}
	flag.StringVar(&opts.metaPath, "m", "", "path to metadata device")
	flag.StringVar(&opts.sourceDir, "s", "", "path to source directory")
	flag.IntVar(&opts.numWorkers, "w", 4, "number of worker threads")
	flag.Parse()

	if opts.metaPath == "" || opts.sourceDir == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Create master and worker writers
	master, workers, err := restore.NewWriters(opts.metaPath, opts.numWorkers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create writers: %v\n", err)
		os.Exit(1)
	}
	defer master.Destroy()

	// Create hardlink tracker
	hlTracker := newHardlinkTracker()

	// Start workers
	var wg sync.WaitGroup
	for i, worker := range workers {
		wg.Add(1)
		go func(w *restore.WorkerWriter, workerNum int) {
			defer wg.Done()

			// Each worker processes a subset of the directory tree
			if err := restorePath(w, hlTracker, opts.sourceDir, 1); err != nil {
				fmt.Fprintf(os.Stderr, "Worker %d failed: %v\n", workerNum, err)
				os.Exit(1)
			}
			// Create root inode for source directory
			rootInfo, err := os.Stat(opts.sourceDir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to stat source directory: %v\n", err)
				os.Exit(1)
			}
			w.CreateInode(getFileInfo(rootInfo))
			err = w.Destroy()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to destroy worker: %v\n", err)
				os.Exit(1)
			}
		}(worker, i)
	}

	// Wait for all workers to complete
	wg.Wait()

	fmt.Println("Restore completed successfully")
}
