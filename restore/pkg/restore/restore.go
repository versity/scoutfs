package restore

/*
#cgo CFLAGS: -I${SRCDIR}/../../../utils/src -I${SRCDIR}/../../../kmod/src
#cgo LDFLAGS: -L${SRCDIR}/../../../utils/src -l:scoutfs_parallel_restore.a -lm

#include <stdlib.h>
#include <linux/types.h>
#include <stdbool.h>
#include <math.h>
#include "sparse.h"
#include "util.h"
#include "format.h"
#include "parallel_restore.h"

// If there are any type conflicts, you might need to add:
// #include "kernel_types.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

const batchSize = 1000
const bufSize = 4096

type WorkerWriter struct {
	writer      *C.struct_scoutfs_parallel_restore_writer
	progressCh  chan *ScoutfsParallelWriterProgress
	fileCreated int64
	devFd       int
	buf         []byte
	wg          *sync.WaitGroup
}

type MasterWriter struct {
	writer     *C.struct_scoutfs_parallel_restore_writer
	progressCh chan *ScoutfsParallelWriterProgress
	workers    []*WorkerWriter
	wg         sync.WaitGroup
	slice      *C.struct_scoutfs_parallel_restore_slice // Add slice field
	progressWg sync.WaitGroup
	devFd      int
	super      *C.struct_scoutfs_super_block
}

type ScoutfsParallelWriterProgress struct {
	Progress *C.struct_scoutfs_parallel_restore_progress
	Slice    *C.struct_scoutfs_parallel_restore_slice
}

func (m *MasterWriter) aggregateProgress() {
	defer m.progressWg.Done()
	for progress := range m.progressCh {
		ret := C.scoutfs_parallel_restore_add_progress(m.writer, progress.Progress)
		if ret != 0 {
			// Handle error appropriately, e.g., log it
			fmt.Printf("Failed to add progress, error code: %d\n", ret)
		}
		if progress.Slice != nil {
			ret = C.scoutfs_parallel_restore_add_slice(m.writer, progress.Slice)
			C.free(unsafe.Pointer(progress.Slice))
			if ret != 0 {
				// Handle error appropriately, e.g., log it
				fmt.Printf("Failed to add slice, error code: %d\n", ret)
			}
		}
		// Free the C-allocated progress structures
		C.free(unsafe.Pointer(progress.Progress))
	}
}

func (m *MasterWriter) Destroy() {
	m.wg.Wait()
	close(m.progressCh)
	m.progressWg.Wait()

	if m.slice != nil {
		C.free(unsafe.Pointer(m.slice)) // Free slice on error
	}
	if m.super != nil {
		C.free(unsafe.Pointer(m.super)) // Free superblock on error
	}
	if m.devFd != 0 {
		syscall.Close(m.devFd)
	}
	// Destroy master writer
	C.scoutfs_parallel_restore_destroy_writer(&m.writer)
}

func NewWriters(path string, numWriters int) (*MasterWriter, []*WorkerWriter, error) {
	if numWriters <= 1 {
		return nil, nil, errors.New("number of writers must be positive")
	}

	devFd, err := syscall.Open(path, syscall.O_DIRECT|syscall.O_RDWR|syscall.O_EXCL, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open metadata device '%s': %v", path, err)
	}

	var masterWriter MasterWriter
	masterWriter.progressCh = make(chan *ScoutfsParallelWriterProgress, numWriters*2)
	masterWriter.workers = make([]*WorkerWriter, numWriters)
	masterWriter.devFd = devFd

	masterWriter.super = (*C.struct_scoutfs_super_block)(C.malloc(C.size_t(unsafe.Sizeof(*masterWriter.super))))
	if masterWriter.super == nil {
		masterWriter.Destroy()
		return nil, nil, errors.New("failed to allocate memory for superblock")
	}

	// Read the superblock from devFd.
	superOffset := C.SCOUTFS_SUPER_BLKNO << C.SCOUTFS_BLOCK_SM_SHIFT
	count, err := syscall.Pread(devFd, (*[1 << 30]byte)(unsafe.Pointer(masterWriter.super))[:C.SCOUTFS_BLOCK_SM_SIZE], int64(superOffset))
	if err != nil {
		masterWriter.Destroy()
		return nil, nil, fmt.Errorf("failed to read superblock: %v", err)
	}
	if count != int(C.SCOUTFS_BLOCK_SM_SIZE) {
		masterWriter.Destroy()
		return nil, nil, fmt.Errorf("failed to read superblock, bytes read: %d", count)
	}

	// Check if the superblock is valid.
	if C.le64_to_cpu(masterWriter.super.flags)&C.SCOUTFS_FLAG_IS_META_BDEV == 0 {
		masterWriter.Destroy()
		return nil, nil, errors.New("superblock is not a metadata device")
	}

	var ret C.int
	// Create master writer
	ret = C.scoutfs_parallel_restore_create_writer(&masterWriter.writer)
	if ret != 0 {
		masterWriter.Destroy()
		return nil, nil, errors.New("failed to create master writer")
	}

	ret = C.scoutfs_parallel_restore_import_super(masterWriter.writer, masterWriter.super, C.int(devFd))
	if ret != 0 {
		masterWriter.Destroy()
		return nil, nil, fmt.Errorf("failed to import superblock, error code: %d", ret)
	}

	// Initialize slices for each worker
	masterWriter.slice = (*C.struct_scoutfs_parallel_restore_slice)(C.malloc(C.size_t(numWriters) *
		C.size_t(unsafe.Sizeof(C.struct_scoutfs_parallel_restore_slice{}))))
	if masterWriter.slice == nil {
		masterWriter.Destroy()
		return nil, nil, errors.New("failed to allocate slices")
	}

	ret = C.scoutfs_parallel_restore_init_slices(masterWriter.writer,
		masterWriter.slice,
		C.int(numWriters))
	if ret != 0 {
		masterWriter.Destroy()
		return nil, nil, errors.New("failed to initialize slices")
	}

	ret = C.scoutfs_parallel_restore_add_slice(masterWriter.writer, masterWriter.slice)
	if ret != 0 {
		masterWriter.Destroy()
		return nil, nil, errors.New("failed to add slice to master writer")
	}

	// Create worker writers
	for i := 1; i < numWriters; i++ {
		worker := &WorkerWriter{
			progressCh: masterWriter.progressCh,
			buf:        make([]byte, bufSize),
		}
		ret = C.scoutfs_parallel_restore_create_writer(&worker.writer)
		if ret != 0 {
			masterWriter.Destroy()
			return nil, nil, errors.New("failed to create worker writer")
		}

		masterWriter.wg.Add(1)

		// Use each slice for the corresponding worker
		slice := (*C.struct_scoutfs_parallel_restore_slice)(unsafe.Pointer(uintptr(unsafe.Pointer(masterWriter.slice)) +
			uintptr(i)*unsafe.Sizeof(C.struct_scoutfs_parallel_restore_slice{})))
		ret = C.scoutfs_parallel_restore_add_slice(worker.writer, slice)
		if ret != 0 {
			C.scoutfs_parallel_restore_destroy_writer(&worker.writer)
			masterWriter.Destroy()
			return nil, nil, errors.New("failed to add slice to worker writer")
		}

		masterWriter.workers[i] = worker
	}
	go masterWriter.aggregateProgress()

	return &masterWriter, masterWriter.workers, nil

}

func (w *WorkerWriter) getProgress(withSlice bool) (*ScoutfsParallelWriterProgress, error) {
	progress := (*C.struct_scoutfs_parallel_restore_progress)(
		C.malloc(C.size_t(unsafe.Sizeof(C.struct_scoutfs_parallel_restore_progress{}))),
	)
	if progress == nil {
		return nil, errors.New("failed to allocate memory for progress")
	}

	// Fetch the current progress from the C library
	ret := C.scoutfs_parallel_restore_get_progress(w.writer, progress)
	if ret != 0 {
		C.free(unsafe.Pointer(progress))
		return nil, fmt.Errorf("failed to get progress, error code: %d", ret)
	}

	var slice *C.struct_scoutfs_parallel_restore_slice
	if withSlice {
		slice = (*C.struct_scoutfs_parallel_restore_slice)(
			C.malloc(C.size_t(unsafe.Sizeof(C.struct_scoutfs_parallel_restore_slice{}))),
		)
		if slice == nil {
			C.free(unsafe.Pointer(progress))
			return nil, errors.New("failed to allocate memory for slice")
		}

		// Optionally fetch the slice information
		ret = C.scoutfs_parallel_restore_get_slice(w.writer, slice)
		if ret != 0 {
			C.free(unsafe.Pointer(progress))
			C.free(unsafe.Pointer(slice))
			return nil, fmt.Errorf("failed to get slice, error code: %d", ret)
		}
	}

	return &ScoutfsParallelWriterProgress{
		Progress: progress,
		Slice:    slice,
	}, nil
}

// writeBufs writes data from the buffer to the device file descriptor.
// It uses scoutfs_parallel_restore_write_buf to get data and pwrite to write it.
func (w *WorkerWriter) writeBufs() (int64, error) {
	var totalWritten int64
	var count int64
	var off int64
	var ret C.int

	// Allocate memory for off and count
	offPtr := (*C.off_t)(unsafe.Pointer(&off))
	countPtr := (*C.size_t)(unsafe.Pointer(&count))

	for {
		ret = C.scoutfs_parallel_restore_write_buf(w.writer, unsafe.Pointer(&w.buf[0]),
			C.size_t(len(w.buf)), offPtr, countPtr)

		if ret != 0 {
			return totalWritten, fmt.Errorf("failed to write buffer: error code %d", ret)
		}

		if count > 0 {
			n, err := syscall.Pwrite(w.devFd, w.buf[:count], off)
			if err != nil {
				return totalWritten, fmt.Errorf("pwrite failed: %v", err)
			}
			if n != int(count) {
				return totalWritten, fmt.Errorf("pwrite wrote %d bytes; expected %d", n, count)
			}
			totalWritten += int64(n)
		}

		if count == 0 {
			break
		}
	}

	return totalWritten, nil
}

func (w *WorkerWriter) InsertEntry(entry *C.struct_scoutfs_parallel_restore_entry) error {
	// Add the entry using the C library
	ret := C.scoutfs_parallel_restore_add_entry(w.writer, entry)
	if ret != 0 {
		return fmt.Errorf("failed to add entry, error code: %d", ret)
	}

	// Increment the fileCreated counter
	w.fileCreated++
	if w.fileCreated >= batchSize {
		_, err := w.writeBufs()
		if err != nil {
			return fmt.Errorf("error writing buffers: %v", err)
		}
		// Allocate memory for progress and slice structures
		progress, err := w.getProgress(false)
		if err != nil {
			return err
		}
		// Send the progress update to the shared progress channel
		w.progressCh <- progress
		// Reset the fileCreated counter
		w.fileCreated = 0
	}

	return nil
}

func (w *WorkerWriter) InsertXattr(xattr *C.struct_scoutfs_parallel_restore_xattr) error {
	ret := C.scoutfs_parallel_restore_add_xattr(w.writer, xattr)
	if ret != 0 {
		return fmt.Errorf("failed to add xattr, error code: %d", ret)
	}
	return nil
}

func (w *WorkerWriter) InsertInode(inode *C.struct_scoutfs_parallel_restore_inode) error {
	ret := C.scoutfs_parallel_restore_add_inode(w.writer, inode)
	if ret != 0 {
		return fmt.Errorf("failed to add inode, error code: %d", ret)
	}
	return nil
}

// should only be called once
func (w *WorkerWriter) Destroy() error {
	defer w.wg.Done()
	// Send final progress if there are remaining entries
	if w.fileCreated > 0 {
		progress := &ScoutfsParallelWriterProgress{
			Progress: (*C.struct_scoutfs_parallel_restore_progress)(C.malloc(C.size_t(unsafe.Sizeof(C.struct_scoutfs_parallel_restore_progress{})))),
			Slice:    (*C.struct_scoutfs_parallel_restore_slice)(C.malloc(C.size_t(unsafe.Sizeof(C.struct_scoutfs_parallel_restore_slice{})))),
		}
		w.progressCh <- progress
		w.fileCreated = 0
	}

	C.scoutfs_parallel_restore_destroy_writer(&w.writer)
	return nil
}
