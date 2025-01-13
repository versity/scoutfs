package restore

/*
#cgo CFLAGS: -I${SRCDIR}/../../../utils/src -I${SRCDIR}/../../../kmod/src
#cgo LDFLAGS: -L${SRCDIR}/../../../utils/src -l:scoutfs_parallel_restore.a -lm

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <stdbool.h>
#include <math.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "parallel_restore.h"

*/
import "C"
import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"github.com/sirupsen/logrus"
)

const batchSize = 1000 // TODO: need to tune this or make it configurable

const bufSize = 2 * 1024 * 1024
const xattrPayloadMax = 65535
const memAlignSize = 4096
const fileNameMax = 255
const pathMax = 4096

type Writer struct {
	logger *logrus.Logger

	// only master writer should close the fd
	devFd int

	// clean up in the destroy function
	buf    unsafe.Pointer                            // need to be freed
	writer *C.struct_scoutfs_parallel_restore_writer // call destroy
}

type WorkerWriter struct {
	id            int
	progressCh    chan *ScoutfsParallelWriterProgress
	entryCreated  int64
	entryInserted int64

	inodeCreated  int64
	inodeInserted int64

	dirCreated   int64
	bytesWritten int64
	complete     bool
	destroyOnce  sync.Once

	xattrPt *C.struct_scoutfs_parallel_restore_xattr
	inodePt *C.struct_scoutfs_parallel_restore_inode
	entryPt *C.struct_scoutfs_parallel_restore_entry

	Writer
}

type MasterWriter struct {
	finishOnce         sync.Once
	workers            []*WorkerWriter
	expectedNumWorkers int

	progressWg sync.WaitGroup
	progressCh chan *ScoutfsParallelWriterProgress

	// clean up in the destroy function
	super *C.struct_scoutfs_super_block
	slice *C.struct_scoutfs_parallel_restore_slice
	Writer
}

// TODO: since this struct will be allocated and freed every time it sent through the channel,
// it might impact the performance, although the progress update should not be very frequent.
// We should monitor it for now and use a buffer pool if needed

type ScoutfsParallelWriterProgress struct {
	Progress *C.struct_scoutfs_parallel_restore_progress
	Slice    *C.struct_scoutfs_parallel_restore_slice
	complete bool
	id       int
}

func (w *WorkerWriter) GetId() int {
	return w.id
}

func (m *MasterWriter) aggregateProgress() {
	defer m.progressWg.Done()
	for progress := range m.progressCh {
		ret := C.scoutfs_parallel_restore_add_progress(m.writer, progress.Progress)
		if ret != 0 {
			m.logger.Fatalf("Failed to add progress %+v, error code: %v\n", progress, ret)
			continue
		}
		C.free(unsafe.Pointer(progress.Progress))

		if progress.Slice != nil && progress.Slice.meta_len != 0 {
			ret = C.scoutfs_parallel_restore_add_slice(m.writer, progress.Slice)
			C.free(unsafe.Pointer(progress.Slice))
			if ret != 0 {
				m.logger.Fatalf("Failed to add slice %+v, error code: %v\n", progress, ret)
				continue
			}
		}
	}
}

func (m *MasterWriter) cleanup() {
	// Clean up remaining resources
	if m.slice != nil {
		C.free(unsafe.Pointer(m.slice))
		m.slice = nil
	}
	if m.writer != nil {
		C.scoutfs_parallel_restore_destroy_writer(&m.writer)
	}
	if m.devFd != 0 {
		_ = syscall.Close(m.devFd)
		m.devFd = 0
	}
	if m.buf != nil {
		C.free(m.buf)
		m.buf = nil
	}
	if m.super != nil {
		C.free(unsafe.Pointer(m.super))
		m.super = nil
	}
	for _, w := range m.workers {
		w.cleanup()
	}
	m.workers = nil
}

func (m *MasterWriter) Finish() {
	m.finishOnce.Do(func() {
		// Wait for all workers to complete
		close(m.progressCh)
		m.progressWg.Wait()

		if _, err := m.writeBuffer(); err != nil {
			m.logger.Fatalf("master writer failed to write buffer during destroy: %s", err)
		}
		// Export and write final superblock
		if m.super != nil {
			ret := C.scoutfs_parallel_restore_export_super(m.writer, m.super)
			if ret != 0 {
				m.logger.Fatalf("Failed to export superblock: %d\n", ret)
			}
			// Write superblock to device
			superOffset := C.SCOUTFS_SUPER_BLKNO << C.SCOUTFS_BLOCK_SM_SHIFT
			count, err := syscall.Pwrite(m.devFd, unsafe.Slice((*byte)(unsafe.Pointer(m.super)),
				C.SCOUTFS_BLOCK_SM_SIZE), int64(superOffset))

			if err != nil {
				m.logger.Fatalf("Failed to write superblock: %d\n", err)
			}
			if count != int(C.SCOUTFS_BLOCK_SM_SIZE) {
				m.logger.Fatalf("written superblock does not match: expect %d, written %d\n",
					int(C.SCOUTFS_BLOCK_SM_SIZE), count)
			}
		} else {
			m.logger.Fatalf("Missing super block")
		}
		m.cleanup()
		m.logger.Infof("Master writer destroyed\n")
	})

}

type Option func(w *Writer)

func WithLogger(logger *logrus.Logger) Option {
	return func(w *Writer) {
		w.logger = logger
	}
}

func (m *MasterWriter) getWorkerSlice(i int) *C.struct_scoutfs_parallel_restore_slice {
	// +1 for master writer
	slices := unsafe.Slice(m.slice, m.expectedNumWorkers+1)
	return &slices[1+i]
}

func createMasterWriter(path string, numWorkerWriters int) (*MasterWriter, error) {
	numSlice := numWorkerWriters + 1 // include master writer

	devFd, err := syscall.Open(path, syscall.O_DIRECT|syscall.O_RDWR|syscall.O_EXCL, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open metadata device '%s': %v", path, err)
	}

	var bufPtr unsafe.Pointer
	if ret := C.posix_memalign(&bufPtr, memAlignSize, bufSize); ret != 0 {
		syscall.Close(devFd)
		return nil, fmt.Errorf("failed to allocate aligned master buffer: %d", ret)
	}

	masterWriter := MasterWriter{
		progressCh:         make(chan *ScoutfsParallelWriterProgress, numWorkerWriters*2),
		workers:            make([]*WorkerWriter, 0, numWorkerWriters),
		expectedNumWorkers: numWorkerWriters,
		Writer: Writer{
			buf:    bufPtr,
			devFd:  devFd,
			logger: logrus.New(),
		},
	}

	var ret C.int
	var super unsafe.Pointer
	ret = C.posix_memalign(&super, memAlignSize, C.SCOUTFS_BLOCK_SM_SIZE)
	if ret != 0 {
		masterWriter.cleanup()
		return nil, fmt.Errorf("failed to allocate aligned memory for superblock: %d", ret)
	}
	masterWriter.super = (*C.struct_scoutfs_super_block)(super)

	superOffset := C.SCOUTFS_SUPER_BLKNO << C.SCOUTFS_BLOCK_SM_SHIFT
	count, err := syscall.Pread(devFd, unsafe.Slice((*byte)(super), C.SCOUTFS_BLOCK_SM_SIZE), int64(superOffset))
	if err != nil {
		masterWriter.cleanup()
		return nil, fmt.Errorf("failed to read superblock: %v", err)
	}
	if count != int(C.SCOUTFS_BLOCK_SM_SIZE) {
		masterWriter.cleanup()
		return nil, fmt.Errorf("failed to read superblock, bytes read: %d", count)
	}

	// Check if the superblock is valid.
	if C.le64_to_cpu(masterWriter.super.flags)&C.SCOUTFS_FLAG_IS_META_BDEV == 0 {
		masterWriter.cleanup()
		return nil, errors.New("superblock is not a metadata device")
	}

	// Create master writer
	ret = C.scoutfs_parallel_restore_create_writer(&masterWriter.writer)
	if ret != 0 {
		masterWriter.cleanup()
		return nil, errors.New("failed to create master writer")
	}

	ret = C.scoutfs_parallel_restore_import_super(masterWriter.writer,
		masterWriter.super, C.int(devFd))
	if ret != 0 {
		masterWriter.cleanup()
		return nil, fmt.Errorf("failed to import superblock, error code: %d", ret)
	}

	// Initialize slices for each worker
	masterWriter.slice = (*C.struct_scoutfs_parallel_restore_slice)(C.calloc(C.size_t(numSlice),
		C.size_t(unsafe.Sizeof(C.struct_scoutfs_parallel_restore_slice{}))))
	if masterWriter.slice == nil {
		masterWriter.cleanup()
		return nil, errors.New("failed to allocate slices")
	}
	slices := unsafe.Slice(masterWriter.slice, numSlice)

	ret = C.scoutfs_parallel_restore_init_slices(masterWriter.writer,
		masterWriter.slice, C.int(numSlice))
	if ret != 0 {
		masterWriter.cleanup()
		return nil, errors.New("failed to initialize slices")
	}

	ret = C.scoutfs_parallel_restore_add_slice(masterWriter.writer, &slices[0])
	if ret != 0 {
		masterWriter.cleanup()
		return nil, errors.New("failed to add slice to master writer")
	}
	return &masterWriter, nil
}

func createWorkerWriter(masterWriter *MasterWriter, id int) (*WorkerWriter, error) {
	worker := &WorkerWriter{
		progressCh: masterWriter.progressCh,
		Writer: Writer{
			devFd:  masterWriter.devFd,
			logger: masterWriter.logger,
		},
		id: id,
	}

	var ret C.int
	ret = C.scoutfs_parallel_restore_create_writer(&worker.writer)
	if ret != 0 {
		worker.cleanup()
		return nil, errors.New("failed to create worker writer")
	}

	var bufPtr unsafe.Pointer
	if ret := C.posix_memalign(&bufPtr, memAlignSize, bufSize); ret != 0 {
		worker.cleanup()
		return nil, fmt.Errorf("failed to allocate aligned worker buffer: %d", ret)
	}
	worker.buf = bufPtr

	worker.xattrPt = (*C.struct_scoutfs_parallel_restore_xattr)(C.malloc(C.size_t(getXattrBufSize())))
	if worker.xattrPt == nil {
		worker.cleanup()
		return nil, fmt.Errorf("failed to allocate aligned worker buffer for xattr: %d", ret)
	}

	worker.inodePt = (*C.struct_scoutfs_parallel_restore_inode)(C.calloc(1,
		C.size_t(unsafe.Sizeof(C.struct_scoutfs_parallel_restore_inode{}))+C.size_t(pathMax)))
	if worker.inodePt == nil {
		worker.cleanup()
		return nil, fmt.Errorf("failed to allocate aligned worker buffer for inode: %d", ret)
	}
	worker.inodePt.target = (*C.char)(unsafe.Add(unsafe.Pointer(worker.inodePt),
		unsafe.Sizeof(C.struct_scoutfs_parallel_restore_inode{})))

	worker.entryPt = (*C.struct_scoutfs_parallel_restore_entry)(C.calloc(1,
		C.size_t(unsafe.Sizeof(C.struct_scoutfs_parallel_restore_entry{}))+C.size_t(fileNameMax)))
	if worker.entryPt == nil {
		worker.cleanup()
		return nil, fmt.Errorf("failed to allocate aligned worker buffer for entry: %d", ret)
	}

	worker.entryPt.name = (*C.char)(unsafe.Add(unsafe.Pointer(worker.entryPt),
		unsafe.Sizeof(C.struct_scoutfs_parallel_restore_entry{})))

	// Use each slice for the corresponding worker
	ret = C.scoutfs_parallel_restore_add_slice(worker.writer, masterWriter.getWorkerSlice(id))
	if ret != 0 {
		worker.cleanup()
		return nil, errors.New("failed to add slice to worker writer")
	}

	return worker, nil
}

func NewWriters(path string, numWorkerWriters int, options ...Option) (*MasterWriter, []*WorkerWriter, error) {
	if numWorkerWriters <= 0 {
		return nil, nil, errors.New("number of writers must be positive")
	}

	masterWriter, err := createMasterWriter(path, numWorkerWriters)
	if err != nil {
		return nil, nil, err
	}

	for _, option := range options {
		option(&masterWriter.Writer)
	}

	// Create worker writers
	for i := 0; i < numWorkerWriters; i++ {
		worker, err := createWorkerWriter(masterWriter, i)
		if err != nil {
			masterWriter.cleanup()
			return nil, nil, err
		}
		masterWriter.workers = append(masterWriter.workers, worker)
	}
	masterWriter.progressWg.Add(1)
	go masterWriter.aggregateProgress()

	return masterWriter, masterWriter.workers, nil
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
		id:       w.id,
	}, nil
}

// writeBuffer writes data from the buffer to the device file descriptor.
// It uses scoutfs_parallel_restore_write_buf to get data and pwrite to write it.
func (w *Writer) writeBuffer() (int64, error) {
	var totalWritten int64
	var count int64
	var off int64
	var ret C.int

	// Allocate memory for off and count
	offPtr := (*C.off_t)(unsafe.Pointer(&off))
	countPtr := (*C.size_t)(unsafe.Pointer(&count))

	for {
		ret = C.scoutfs_parallel_restore_write_buf(w.writer, w.buf,
			C.size_t(bufSize), offPtr, countPtr)

		if ret != 0 {
			return totalWritten, fmt.Errorf("failed to write buffer: error code %d", ret)
		}

		if count > 0 {
			n, err := syscall.Pwrite(w.devFd, unsafe.Slice((*byte)(w.buf), count), off)
			if err != nil {
				return totalWritten, fmt.Errorf("pwrite failed: %v", err)
			}
			if n != int(count) {
				return totalWritten, fmt.Errorf("pwrite wrote %d bytes; expected %d", n, count)
			}
			totalWritten += int64(n)
		} else {
			break
		}
	}

	return totalWritten, nil
}

func (w *WorkerWriter) insertEntry(entry *C.struct_scoutfs_parallel_restore_entry) error {
	// Add the entry using the C library
	ret := C.scoutfs_parallel_restore_add_entry(w.writer, entry)
	if ret != 0 {
		return fmt.Errorf("failed to add entry, error code: %d", ret)
	}

	// Increment the entryCreated counter
	w.entryCreated++
	if w.entryCreated+w.inodeCreated >= batchSize {
		if err := w.flushBuffer(false); err != nil {
			return err
		}
	}

	return nil
}

func (w *WorkerWriter) insertInode(inode *C.struct_scoutfs_parallel_restore_inode) error {
	ret := C.scoutfs_parallel_restore_add_inode(w.writer, inode)
	if ret != 0 {
		return fmt.Errorf("failed to add inode, error code: %d", ret)
	}
	w.inodeCreated++
	if w.entryCreated+w.inodeCreated >= batchSize {
		if err := w.flushBuffer(false); err != nil {
			return err
		}
	}
	return nil
}

func (w *WorkerWriter) flushBuffer(lastProgress bool) error {
	_, err := w.writeBuffer()
	if err != nil {
		return fmt.Errorf("error writing buffers: %v", err)
	}
	// Allocate memory for progress and slice structures
	progress, err := w.getProgress(lastProgress)
	if err != nil {
		return err
	}
	// Send the progress update to the shared progress channel
	w.progressCh <- progress

	w.entryInserted += w.entryCreated
	w.entryCreated = 0
	w.inodeInserted += w.inodeCreated
	w.inodeCreated = 0
	return nil
}

func (w *WorkerWriter) cleanup() {
	if w.buf != nil {
		C.free(w.buf)
		w.buf = nil
	}
	if w.xattrPt != nil {
		C.free(unsafe.Pointer(w.xattrPt))
		w.xattrPt = nil
	}
	if w.inodePt != nil {
		C.free(unsafe.Pointer(w.inodePt))
		w.inodePt = nil
	}
	if w.entryPt != nil {
		C.free(unsafe.Pointer(w.entryPt))
		w.entryPt = nil
	}
	if w.writer != nil {
		C.scoutfs_parallel_restore_destroy_writer(&w.writer)
		w.writer = nil
	}
}

func (w *WorkerWriter) Finish() {
	w.destroyOnce.Do(
		func() {
			err := w.flushBuffer(true)
			if err != nil {
				w.logger.Fatalf("worker failed to write buffer during destroy: %v", err)
			}
			w.cleanup()
		})
}

// Add these new types and functions to the existing restore.go file

type InodeInfo struct {
	Ino           uint64
	Mode          uint32
	Uid           uint32
	Gid           uint32
	Size          uint64
	Rdev          uint64
	AtimeSec      int64
	AtimeNsec     int64
	MtimeSec      int64
	MtimeNsec     int64
	CtimeSec      int64
	CtimeNsec     int64
	NrSubdirs     uint64
	NameBytes     uint64
	IsDir         bool
	IsRegular     bool
	Target        string
	DataVersion   uint64
	RetentionFlag bool
}

type EntryInfo struct {
	DirInode uint64
	Position uint64
	Inode    uint64
	Mode     uint32
	Name     string
}

type XAttr struct {
	Name  string
	Value []byte
}

// Add these constants
const (
	SCOUTFS_IOC_MAGIC = 0xBF
)

func (w *WorkerWriter) resetInode() {
	C.memset(unsafe.Pointer(w.inodePt), 0,
		C.size_t(unsafe.Sizeof(C.struct_scoutfs_parallel_restore_inode{}))+C.size_t(pathMax))

	w.inodePt.target = (*C.char)(unsafe.Add(unsafe.Pointer(w.inodePt),
		unsafe.Sizeof(C.struct_scoutfs_parallel_restore_inode{})))
}

// CreateInode creates a C inode structure from InodeInfo
func (w *WorkerWriter) CreateInode(info InodeInfo) error {
	w.resetInode()
	inode := w.inodePt

	if info.Target != "" {
		targetBytes := []byte(info.Target)
		// to accomendate for the null terminator
		if len(targetBytes) >= pathMax {
			return fmt.Errorf("target string too long: %d bytes", len(targetBytes))
		}
		// Copy the target string into the preallocated buffer
		C.memcpy(
			unsafe.Pointer(inode.target),
			unsafe.Pointer(&targetBytes[0]),
			C.size_t(len(targetBytes)),
		)
		inode.target_len = C.uint(len(targetBytes)) + 1
	} else {
		inode.target_len = 0
	}

	inode.ino = C.__u64(info.Ino)
	inode.mode = C.__u32(info.Mode)
	inode.uid = C.__u32(info.Uid)
	inode.gid = C.__u32(info.Gid)
	inode.size = C.__u64(info.Size)
	inode.rdev = C.uint(info.Rdev)

	inode.atime.tv_sec = C.__time_t(info.AtimeSec)
	inode.atime.tv_nsec = C.long(info.AtimeNsec)
	inode.mtime.tv_sec = C.__time_t(info.MtimeSec)
	inode.mtime.tv_nsec = C.long(info.MtimeNsec)
	inode.ctime.tv_sec = C.__time_t(info.CtimeSec)
	inode.ctime.tv_nsec = C.long(info.CtimeNsec)
	inode.crtime = inode.ctime
	inode.meta_seq = C.__u64(0)
	inode.data_seq = C.__u64(0)
	inode.nr_subdirs = C.__u64(info.NrSubdirs)
	inode.total_entry_name_bytes = C.__u64(info.NameBytes)
	inode.data_version = C.__u64(info.DataVersion)

	if info.RetentionFlag {
		inode.flags = C.SCOUTFS_INO_FLAG_RETENTION
	}

	if info.IsRegular {
		if info.Size > 0 {
			inode.offline = C.bool(true)
		} else {
			inode.offline = C.bool(false)
		}
	}

	return w.insertInode(inode)
}

func (w *WorkerWriter) resetEntry() {
	C.memset(unsafe.Pointer(w.entryPt), 0,
		C.size_t(unsafe.Sizeof(C.struct_scoutfs_parallel_restore_entry{}))+C.size_t(fileNameMax))

	w.entryPt.name = (*C.char)(unsafe.Add(unsafe.Pointer(w.entryPt),
		unsafe.Sizeof(C.struct_scoutfs_parallel_restore_entry{})))
}

// CreateEntry creates a directory entry
func (w *WorkerWriter) CreateEntry(entryInfo EntryInfo) error {
	w.resetEntry()
	entry := w.entryPt

	entry.dir_ino = C.__u64(entryInfo.DirInode)
	entry.pos = C.__u64(entryInfo.Position)
	entry.ino = C.__u64(entryInfo.Inode)
	entry.mode = C.__u32(entryInfo.Mode)

	nameBytes := []byte(entryInfo.Name)
	if len(nameBytes) > fileNameMax {
		w.logger.Fatalf("name %v too long: %d", entryInfo.Name, len(nameBytes))
	}
	C.memcpy(unsafe.Pointer(entry.name), unsafe.Pointer(&nameBytes[0]), C.size_t(len(nameBytes)))

	entry.name_len = C.uint(len(entryInfo.Name))

	ret := C.scoutfs_parallel_restore_add_entry(w.writer, entry)
	if ret != 0 {
		return fmt.Errorf("failed to add entry, error code: %d", ret)
	}
	return nil
}
func getXattrBufSize() uintptr {
	return unsafe.Sizeof(C.struct_scoutfs_parallel_restore_xattr{}) +
		uintptr(C.SCOUTFS_XATTR_MAX_NAME_LEN) + uintptr(xattrPayloadMax)
}

func (w *WorkerWriter) getXattrBuf() *C.struct_scoutfs_parallel_restore_xattr {
	// Calculate total size of the buffer
	totalSize := getXattrBufSize()

	// Create a byte slice that represents the memory region
	buf := unsafe.Slice((*byte)(unsafe.Pointer(w.xattrPt)), totalSize)

	// Zero out the memory
	for i := range buf {
		buf[i] = 0
	}

	return w.xattrPt
}

func (w *WorkerWriter) SetXattr(ino uint64, pos uint64, name string, value []byte) error {
	nameLen := len(name)
	valueLen := len(value)

	if nameLen > C.SCOUTFS_XATTR_MAX_NAME_LEN {
		return fmt.Errorf("xattr name too long")
	}
	if valueLen > xattrPayloadMax {
		return fmt.Errorf("xattr value too long")
	}

	xattr := w.getXattrBuf()
	xattr.ino = C.__u64(ino)
	xattr.pos = C.__u64(pos)
	xattr.name_len = C.uint(nameLen)
	xattr.value_len = C.__u32(valueLen)

	xattr.name = (*C.char)(unsafe.Add(unsafe.Pointer(xattr),
		unsafe.Sizeof(C.struct_scoutfs_parallel_restore_xattr{})))
	namePtr := unsafe.Slice((*byte)(unsafe.Pointer(xattr.name)), len(name))
	copy(namePtr, []byte(name))

	xattr.value = unsafe.Add(unsafe.Pointer(xattr.name), uintptr(C.SCOUTFS_XATTR_MAX_NAME_LEN))
	valuePtr := unsafe.Slice((*byte)(unsafe.Pointer(xattr.value)), valueLen)
	copy(valuePtr, value)

	ret := C.scoutfs_parallel_restore_add_xattr(w.writer, xattr)
	if ret != 0 {
		return fmt.Errorf("add xattr failed: %d", ret)
	}
	return nil
}
