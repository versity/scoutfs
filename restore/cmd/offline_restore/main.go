package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"restore/pkg/restore"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/versity/scoutam/acct"
	"github.com/versity/scoutam/cmd/dump-restore/cwalk"
	"github.com/versity/scoutam/cmd/dump-restore/dumpdb"
	scoutamfs "github.com/versity/scoutam/fs"
	"github.com/versity/scoutam/retention"
	"golang.org/x/sys/unix"
)

const topid = 1

var restoreCmd = &cobra.Command{
	Use:   "offline_restore",
	Short: "Restore files from a scoutamfs dump database",
	Long: `Restore files from a scoutamfs dump database to a scoutamfs mount point. 
This tool requires both a mounted scoutamfs filesystem and a dump database.`,
	Example: `  # Restore with 4 workers
  offline_restore --path /mnt/scoutamfs --database /path/to/dump.db --workers 4
  
  # Restore with default single worker
  offline_restore -p /mnt/scoutamfs -d /path/to/dump.db`,
	Run: doRestore,
}

// TODO: export the following function and const from scoutam
func compressData(b []byte) ([]byte, error) {
	var bb bytes.Buffer
	gz := gzip.NewWriter(&bb)
	if _, err := gz.Write(b); err != nil {
		return nil, err
	}
	if err := gz.Flush(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

const systemPrefix = "scoutfs.hide."
const copyprefix = systemPrefix + "sam_copy_"
const xattrPayloadMax = 65535
const systemSearchPrefix = systemPrefix + "srch."
const volidxprefix = systemSearchPrefix + volPrefix
const volPrefix = "sam_vol_"
const flagskey = systemPrefix + "sam_flags"
const restimekey = systemPrefix + "sam_restime"
const reqcopieskey = systemPrefix + "sam_reqcopies"
const acctPrefix = systemPrefix + "totl.acct"
const ifREQ = 57344 //  vsm removable media mode
const vsmcsumtype = systemPrefix + "sam_vsm_csumtype"
const vsmcsum = systemPrefix + "sam_vsm_csum"

type xattr struct {
	Name  string
	Value []byte
}

func getXattrFromCopy(ai *scoutamfs.ArchiveInfo) ([]xattr, error) {
	xattrs := make([]xattr, 0)

	b, err := json.Marshal(&ai)
	if err != nil {
		return nil, err
	}
	value, err := compressData(b)
	if err != nil {
		return nil, err
	}
	if len(value) > xattrPayloadMax {
		return nil, fmt.Errorf("xattr value is too large")
	}

	key := fmt.Sprintf("%s%d", copyprefix, ai.Copy)
	xattrs = append(xattrs, xattr{Name: key, Value: value})

	for _, vol := range ai.GetVols() {
		xattrs = append(xattrs, xattr{Name: fmt.Sprintf("%s%s", volidxprefix, vol.GetVolume())})
		xattrs = append(xattrs, xattr{Name: fmt.Sprintf("%s%s_%x", volidxprefix, vol.GetVolume(), vol.GetPosition())})
	}

	return xattrs, nil
}

func getSingleAcctXattr(id1, id2, val uint64) (xattr, error) {
	acctKey := fmt.Sprintf("%v.%v.%v.%v", acctPrefix, acct.GetScoutamID(), id1, id2)
	switch id1 {
	case acct.Unmatched, acct.Damaged, acct.NoArchive:
		return xattr{}, fmt.Errorf("invalid id1 %v for acct xattr", id1)
	default:
		return xattr{Name: acctKey, Value: []byte(fmt.Sprintf("%v", val))}, nil
	}
}

func getAcctXattr(r scoutamfs.RestoreInfo) ([]xattr, error) {
	xattrs := make([]xattr, 0)
	v, err := getSingleAcctXattr(acct.UID, uint64(r.UID), r.Size)
	if err != nil {
		return nil, fmt.Errorf("could not get uid acct xattr: %w", err)
	}
	xattrs = append(xattrs, v)

	v, err = getSingleAcctXattr(acct.GID, uint64(r.GID), r.Size)
	if err != nil {
		return nil, fmt.Errorf("could not get gid acct xattr: %w", err)
	}
	xattrs = append(xattrs, v)

	if r.Project != 0 {
		v, err := getSingleAcctXattr(acct.Project, r.Project, r.Size)
		if err != nil {
			return nil, fmt.Errorf("could not get project acct xattr: %w", err)
		}
		xattrs = append(xattrs, v)
	}

	if r.Size == 0 {
		v, err := getSingleAcctXattr(acct.UIDCache, uint64(r.UID), 0)
		if err != nil {
			return nil, fmt.Errorf("could not get uidcache acct xattr: %w", err)
		}
		xattrs = append(xattrs, v)

		v, err = getSingleAcctXattr(acct.GIDCache, uint64(r.GID), 0)
		if err != nil {
			return nil, fmt.Errorf("could not get gidcache acct xattr: %w", err)
		}
		xattrs = append(xattrs, v)

		if r.Project != 0 {
			v, err := getSingleAcctXattr(acct.Project, r.Project, 0)
			if err != nil {
				return nil, fmt.Errorf("could not get project acct xattr: %w", err)
			}
			xattrs = append(xattrs, v)
		}
	}
	return xattrs, nil
}

func getRetentionXattr(r scoutamfs.RestoreInfo) ([]xattr, error) {
	if r.RtnExpireTime == 0 {
		return nil, nil
	}
	expireTime := time.Unix(int64(r.RtnExpireTime), 0)
	var res []xattr
	// TODO: how to check FS format version ScoutfsInfo.GetFormatVersion()

	if expireTime.Before(time.Now()) {
		key := scoutamfs.GetIndexKey(retention.IndexName, scoutamfs.IndxIDRetentionExpired, r.RtnExpireTime)
		return []xattr{{Name: key}}, nil
	}
	// TODO: set retention

	key := scoutamfs.GetIndexKey(retention.IndexName, scoutamfs.IndxIDRetentionActive, r.RtnExpireTime)
	res = append(res, xattr{Name: key})
	return res, nil
}

func getXattrFromRestoreInfo(r scoutamfs.RestoreInfo) ([]xattr, error) {
	if r.VsmMode&syscall.S_IFMT == ifREQ {
		return nil, fmt.Errorf("unhandled filetype (vsm removable media)")
	}
	var xattrs []xattr
	for k, v := range r.Xattrs {
		xattrs = append(xattrs, xattr{Name: k, Value: []byte(v)})
	}

	if r.VsmCsum.Csum != "" {
		xattrs = append(xattrs, xattr{Name: vsmcsumtype, Value: []byte(fmt.Sprintf("%v", r.VsmCsum.Algo))})
		xattrs = append(xattrs, xattr{Name: vsmcsum, Value: []byte(r.VsmCsum.Csum)})
	}

	for _, v := range r.Copies {
		xattrFromCopy, err := getXattrFromCopy(&v)
		if err != nil {
			return nil, fmt.Errorf("could not get xattr from copy %w", err)
		}
		xattrs = append(xattrs, xattrFromCopy...)
	}

	if r.Flags != 0 {
		r.Flags &= ^scoutamfs.Staging
		b, err := json.Marshal(r.Flags)
		if err != nil {
			return nil, fmt.Errorf("could not marshal flags: %w", err)
		}
		xattrs = append(xattrs, xattr{Name: flagskey, Value: b})
	}

	if !r.ResTime.IsZero() {
		b, err := json.Marshal(r.ResTime)
		if err != nil {
			return nil, fmt.Errorf("could not marshal residence time: %w", err)
		}
		xattrs = append(xattrs, xattr{Name: restimekey, Value: b})
	}

	if r.ReqCopies >= 0 {
		b, err := json.Marshal(r.ReqCopies)
		if err != nil {
			return nil, fmt.Errorf("could not marshal required copies: %w", err)
		}
		xattrs = append(xattrs, xattr{Name: reqcopieskey, Value: b})
	}

	retentionXattr, err := getRetentionXattr(r)
	if err != nil {
		return nil, fmt.Errorf("could not get retention xattr: %w", err)
	}
	xattrs = append(xattrs, retentionXattr...)

	if !r.Mode.IsRegular() {
		return xattrs, nil
	}

	accountXattrs, err := getAcctXattr(r)
	if err != nil {
		return nil, fmt.Errorf("could not get acct xattr: %w", err)
	}
	xattrs = append(xattrs, accountXattrs...)

	return xattrs, nil
}

func convertRestoreInfoToInodeInfo(info scoutamfs.RestoreInfo, mode uint32) restore.InodeInfo {
	if info.Inode == 0 {
		info.Inode = 1
	}
	var retentionFlag bool

	if expireTime := time.Unix(int64(info.RtnExpireTime), 0); !expireTime.IsZero() {
		retentionFlag = true
	}

	return restore.InodeInfo{
		Ino:           info.Inode,
		Mode:          mode,
		Uid:           info.UID,
		Gid:           info.GID,
		Size:          info.Size,
		Rdev:          unix.Mkdev(uint32(info.Devmajor), uint32(info.Devminor)),
		AtimeSec:      info.Atime.Unix(),
		AtimeNsec:     int64(info.Atime.Nanosecond()),
		MtimeSec:      info.Mtime.Unix(),
		MtimeNsec:     int64(info.Mtime.Nanosecond()),
		CtimeSec:      info.Ctime.Unix(),
		CtimeNsec:     int64(info.Ctime.Nanosecond()),
		NrSubdirs:     info.NumSubDirs,
		NameBytes:     info.TotalEntryNameInBytes,
		IsDir:         info.Mode.IsDir(),
		IsRegular:     info.Mode.IsRegular(),
		Target:        info.Symlink,
		DataVersion:   info.Version,
		RetentionFlag: retentionFlag,
	}
}

func convertFileModeToUnix(mode fs.FileMode) uint32 {
	var unixMode uint32

	switch {
	case mode.IsDir():
		unixMode |= unix.S_IFDIR
	case mode&fs.ModeSymlink != 0:
		unixMode |= unix.S_IFLNK
	case mode&fs.ModeSocket != 0:
		unixMode |= unix.S_IFSOCK
	case mode&fs.ModeNamedPipe != 0:
		unixMode |= unix.S_IFIFO
	case mode&fs.ModeDevice != 0:
		if mode&fs.ModeCharDevice != 0 {
			unixMode |= unix.S_IFCHR
		} else {
			unixMode |= unix.S_IFBLK
		}
	case mode.IsRegular():
		unixMode |= unix.S_IFREG
	default:
		unixMode |= 0x0000 // Unknown file type
	}

	// Set additional mode bits
	if mode&os.ModeSetuid != 0 {
		unixMode |= unix.S_ISUID
	}
	if mode&os.ModeSetgid != 0 {
		unixMode |= unix.S_ISGID
	}
	if mode&os.ModeSticky != 0 {
		unixMode |= unix.S_ISVTX // sticky bit
	}

	// Permission bits
	unixMode |= uint32(mode.Perm())

	return unixMode
}

func init() {
	// Required flags
	restoreCmd.Flags().StringP("dev", "m", "", "path metadata device")
	_ = restoreCmd.MarkFlagRequired("dev")

	restoreCmd.Flags().StringP("database", "d", "", "path to scoutamfs dump database")
	_ = restoreCmd.MarkFlagRequired("database")

	// Optional flags
	restoreCmd.Flags().IntP("workers", "w", 1, "number of parallel workers")
	restoreCmd.Flags().IntP("version", "v", 0, "scoutamfs version to restore")
}

type restoreData struct {
	entryInfo *restore.EntryInfo
	inodeInfo *restore.InodeInfo
	xattrs    []xattr
	path      string // only for log purpose
}

func doRestore(cmd *cobra.Command, _ []string) {
	// Get flag values
	dev, err := cmd.Flags().GetString("dev")
	if err != nil {
		log.Fatalf("failed to get --dev flag: %v", err)
	}

	database, err := cmd.Flags().GetString("database")
	if err != nil {
		log.Fatalf("failed to get --database flag: %v", err)
	}

	workers, err := cmd.Flags().GetInt("workers")
	if err != nil {
		log.Fatalf("failed to get --workers flag: %v", err)
	}

	version, err := cmd.Flags().GetInt("version")
	if err != nil {
		log.Fatalf("failed to get --version flag: %v", err)
	}

	log.Infof("dev: %s, database: %s, version: %d, workers: %d", dev, database, version, workers)

	db, err := dumpdb.NewBadgerDB(database, dumpdb.WithRO())
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	masterWriter, workerWriters, err := restore.NewWriters(dev, workers, restore.WithLogger(log.StandardLogger()))
	if err != nil {
		log.Fatalf("failed create writer: %v", err)
	}

	restoreCh := make(chan *restoreData, workers*10)

	var wg sync.WaitGroup

	for _, w := range workerWriters {
		wg.Add(1)
		go func() {
			ProcessRestoreTask(w, restoreCh)
			wg.Done()
		}()
	}

	walkFn := func(path string, info scoutamfs.RestoreInfo, err error) error {
		if err != nil {
			log.Fatalf("failed to restore %s: %v", path, err)
			return err
		}

		mode := convertFileModeToUnix(info.Mode)
		var entryInfo *restore.EntryInfo

		if info.Inode != topid {
			// no entry is created for the root dir
			entryInfo = &restore.EntryInfo{
				DirInode: info.ParentInode,
				Position: info.Position,
				Inode:    info.Inode,
				Mode:     mode,
				Name:     filepath.Base(info.Name),
			}
		}

		inodeInfo := convertRestoreInfoToInodeInfo(info, mode)
		var xattrs []xattr
		// TODO: directory xattr is not preserved in dump-restore
		if info.Mode.IsRegular() {
			xattrs, err = getXattrFromRestoreInfo(info)
		}

		restoreCh <- &restoreData{
			entryInfo: entryInfo,
			inodeInfo: &inodeInfo,
			path:      path,
			xattrs:    xattrs,
		}
		return nil
	}

	err = cwalk.Walk(topid, uint64(version), walkFn, db, workers, nil, true)
	if err != nil {
		log.Fatalf("failed to walk: %v", err)
	}
	close(restoreCh)
	wg.Wait()
	masterWriter.Finish()
}

func main() {
	_ = restoreCmd.Execute()
}

func ProcessRestoreTask(worker *restore.WorkerWriter, restoreCh chan *restoreData) {
	for r := range restoreCh {
		if r.entryInfo != nil {
			if err := worker.CreateEntry(*r.entryInfo); err != nil {
				log.Fatalf("failed to restore entry for path %v: %v", r.path, err)
			}
		}
		if r.inodeInfo != nil {
			if err := worker.CreateInode(*r.inodeInfo); err != nil {
				log.Fatalf("failed to restore inode for path %v: %v", r.path, err)
			}
		} else {
			log.Fatalf("missing inode info for path %v", r.path)
		}
		var pos uint64
		for _, v := range r.xattrs {
			if err := worker.SetXattr(r.inodeInfo.Ino, pos, v.Name, v.Value); err != nil {
				log.Fatalf("failed to restore xattr for path %v: %v", r.path, err)
			} else {
				pos++
			}
		}
	}
	worker.Finish()
}
