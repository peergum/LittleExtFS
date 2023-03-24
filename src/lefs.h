/*
 * The little filesystem
 *
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef LEFS_H
#define LEFS_H

#include "Particle.h"

#include <stdint.h>
#include <stdbool.h>


#ifdef __cplusplus

namespace nsLittleExtFS {

extern "C"
{
#endif


/// Version info ///

// Software library version
// Major (top-nibble), incremented on backwards incompatible changes
// Minor (bottom-nibble), incremented on feature additions
#define LEFS_VERSION 0x00010007
#define LEFS_VERSION_MAJOR (0xffff & (LEFS_VERSION >> 16))
#define LEFS_VERSION_MINOR (0xffff & (LEFS_VERSION >>  0))

// Version of On-disk data structures
// Major (top-nibble), incremented on backwards incompatible changes
// Minor (bottom-nibble), incremented on feature additions
#define LEFS_DISK_VERSION 0x00010001
#define LEFS_DISK_VERSION_MAJOR (0xffff & (LEFS_DISK_VERSION >> 16))
#define LEFS_DISK_VERSION_MINOR (0xffff & (LEFS_DISK_VERSION >>  0))


/// Definitions ///

// Type definitions
typedef uint32_t lefs_size_t;
typedef uint32_t lefs_off_t;

typedef int32_t  lefs_ssize_t;
typedef int32_t  lefs_soff_t;

typedef uint32_t lefs_block_t;

// Max name size in bytes
#ifndef LEFS_NAME_MAX
#define LEFS_NAME_MAX 255
#endif

// Max file size in bytes
#ifndef LEFS_FILE_MAX
#define LEFS_FILE_MAX 2147483647
#endif

// Possible error codes, these are negative to allow
// valid positive return values
enum lefs_error {
    LEFS_ERR_OK       = 0,    // No error
    LEFS_ERR_IO       = -5,   // Error during device operation
    LEFS_ERR_CORRUPT  = -52,  // Corrupted
    LEFS_ERR_NOENT    = -2,   // No directory entry
    LEFS_ERR_EXIST    = -17,  // Entry already exists
    LEFS_ERR_NOTDIR   = -20,  // Entry is not a dir
    LEFS_ERR_ISDIR    = -21,  // Entry is a dir
    LEFS_ERR_NOTEMPTY = -39,  // Dir is not empty
    LEFS_ERR_BADF     = -9,   // Bad file number
    LEFS_ERR_FBIG     = -27,  // File too large
    LEFS_ERR_INVAL    = -22,  // Invalid parameter
    LEFS_ERR_NOSPC    = -28,  // No space left on device
    LEFS_ERR_NOMEM    = -12,  // No more memory available
};

// File types
enum lefs_type {
    LEFS_TYPE_REG        = 0x11,
    LEFS_TYPE_DIR        = 0x22,
    LEFS_TYPE_SUPERBLOCK = 0x2e,
};

// File open flags
enum lefs_open_flags {
    // open flags
    LEFS_O_RDONLY = 1,        // Open a file as read only
    LEFS_O_WRONLY = 2,        // Open a file as write only
    LEFS_O_RDWR   = 3,        // Open a file as read and write
    LEFS_O_CREAT  = 0x0100,   // Create a file if it does not exist
    LEFS_O_EXCL   = 0x0200,   // Fail if a file already exists
    LEFS_O_TRUNC  = 0x0400,   // Truncate the existing file to zero size
    LEFS_O_APPEND = 0x0800,   // Move to end of file on every write

    // internally used flags
    LEFS_F_DIRTY   = 0x10000, // File does not match storage
    LEFS_F_WRITING = 0x20000, // File has been written since last flush
    LEFS_F_READING = 0x40000, // File has been read since last flush
    LEFS_F_ERRED   = 0x80000, // An error occured during write
};

// File seek flags
enum lefs_whence_flags {
    LEFS_SEEK_SET = 0,   // Seek relative to an absolute position
    LEFS_SEEK_CUR = 1,   // Seek relative to the current file position
    LEFS_SEEK_END = 2,   // Seek relative to the end of the file
};


// Configuration provided during initialization of the littleextfs
struct lefs_config {
    // Opaque user provided context that can be used to pass
    // information to the block device operations
    void *context;

    // Read a region in a block. Negative error codes are propogated
    // to the user.
    int (*read)(const struct lefs_config *c, lefs_block_t block,
            lefs_off_t off, void *buffer, lefs_size_t size);

    // Program a region in a block. The block must have previously
    // been erased. Negative error codes are propogated to the user.
    // May return LEFS_ERR_CORRUPT if the block should be considered bad.
    int (*prog)(const struct lefs_config *c, lefs_block_t block,
            lefs_off_t off, const void *buffer, lefs_size_t size);

    // Erase a block. A block must be erased before being programmed.
    // The state of an erased block is undefined. Negative error codes
    // are propogated to the user.
    // May return LEFS_ERR_CORRUPT if the block should be considered bad.
    int (*erase)(const struct lefs_config *c, lefs_block_t block);

    // Sync the state of the underlying block device. Negative error codes
    // are propogated to the user.
    int (*sync)(const struct lefs_config *c);

    // Minimum size of a block read. This determines the size of read buffers.
    // This may be larger than the physical read size to improve performance
    // by caching more of the block device.
    lefs_size_t read_size;

    // Minimum size of a block program. This determines the size of program
    // buffers. This may be larger than the physical program size to improve
    // performance by caching more of the block device.
    // Must be a multiple of the read size.
    lefs_size_t prog_size;

    // Size of an erasable block. This does not impact ram consumption and
    // may be larger than the physical erase size. However, this should be
    // kept small as each file currently takes up an entire block.
    // Must be a multiple of the program size.
    lefs_size_t block_size;

    // Number of erasable blocks on the device.
    lefs_size_t block_count;

    // Number of blocks to lookahead during block allocation. A larger
    // lookahead reduces the number of passes required to allocate a block.
    // The lookahead buffer requires only 1 bit per block so it can be quite
    // large with little ram impact. Should be a multiple of 32.
    lefs_size_t lookahead;

    // Optional, statically allocated read buffer. Must be read sized.
    void *read_buffer;

    // Optional, statically allocated program buffer. Must be program sized.
    void *prog_buffer;

    // Optional, statically allocated lookahead buffer. Must be 1 bit per
    // lookahead block.
    void *lookahead_buffer;

    // Optional, statically allocated buffer for files. Must be program sized.
    // If enabled, only one file may be opened at a time.
    void *file_buffer;
};

// Optional configuration provided during lefs_file_opencfg
struct lefs_file_config {
    // Optional, statically allocated buffer for files. Must be program sized.
    // If NULL, malloc will be used by default.
    void *buffer;
};

// File info structure
struct lefs_info {
    // Type of the file, either LEFS_TYPE_REG or LEFS_TYPE_DIR
    uint8_t type;

    // Size of the file, only valid for REG files
    lefs_size_t size;

    // Name of the file stored as a null-terminated string
    char name[LEFS_NAME_MAX+1];
};


/// littleextfs data structures ///
typedef struct lefs_disk_entry {
  uint8_t type;
  uint8_t elen;
  uint8_t alen;
  uint8_t nlen;
  union {
    struct {
      lefs_block_t head;
      lefs_size_t size;
    } file;
    lefs_block_t dir[2];
  } u;
} lefs_disk_entry_t;

typedef struct lefs_entry {
    lefs_off_t off;

    lefs_disk_entry_t d;
} lefs_entry_t;

typedef struct lefs_cache {
    lefs_block_t block;
    lefs_off_t off;
    uint8_t *buffer;
} lefs_cache_t;

typedef struct lefs_file {
    struct lefs_file *next;
    lefs_block_t pair[2];
    lefs_off_t poff;

    lefs_block_t head;
    lefs_size_t size;

    const struct lefs_file_config *cfg;
    uint32_t flags;
    lefs_off_t pos;
    lefs_block_t block;
    lefs_off_t off;
    lefs_cache_t cache;
} lefs_file_t;

typedef struct lefs_disk_dir {
  uint32_t rev;
  lefs_size_t size;
  lefs_block_t tail[2];
} lefs_disk_dir_t;

typedef struct lefs_dir {
  struct lefs_dir *next;
  lefs_block_t pair[2];
  lefs_off_t off;

  lefs_block_t head[2];
  lefs_off_t pos;

  lefs_disk_dir_t d;
} lefs_dir_t;

typedef struct lefs_disk_superblock {
  uint8_t type;
  uint8_t elen;
  uint8_t alen;
  uint8_t nlen;
  lefs_block_t root[2];
  uint32_t block_size;
  uint32_t block_count;
  uint32_t version;
  char magic[8];
} lefs_disk_superblock_t;

typedef struct lefs_superblock {
  lefs_off_t off;

  lefs_disk_superblock_t d;
} lefs_superblock_t;

typedef struct lefs_free {
    lefs_block_t off;
    lefs_block_t size;
    lefs_block_t i;
    lefs_block_t ack;
    uint32_t *buffer;
} lefs_free_t;

// The littleextfs type
typedef struct lefs {
    const struct lefs_config *cfg;

    lefs_block_t root[2];
    lefs_file_t *files;
    lefs_dir_t *dirs;

    lefs_cache_t rcache;
    lefs_cache_t pcache;

    lefs_free_t free;
    bool deorphaned;
    bool moving;
} lefs_t;


/// Filesystem functions ///

// Format a block device with the littleextfs
//
// Requires a littleextfs object and config struct. This clobbers the littleextfs
// object, and does not leave the filesystem mounted. The config struct must
// be zeroed for defaults and backwards compatibility.
//
// Returns a negative error code on failure.
int _lefs_format(lefs_t *lefs, const struct lefs_config *config);

// Mounts a littleextfs
//
// Requires a littleextfs object and config struct. Multiple filesystems
// may be mounted simultaneously with multiple littleextfs objects. Both
// lefs and config must be allocated while mounted. The config struct must
// be zeroed for defaults and backwards compatibility.
//
// Returns a negative error code on failure.
int _lefs_mount(lefs_t *lefs, const struct lefs_config *config);

// Unmounts a littleextfs
//
// Does nothing besides releasing any allocated resources.
// Returns a negative error code on failure.
int _lefs_unmount(lefs_t *lefs);

/// General operations ///

// Removes a file or directory
//
// If removing a directory, the directory must be empty.
// Returns a negative error code on failure.
int _lefs_remove(lefs_t *lefs, const char *path);

// Rename or move a file or directory
//
// If the destination exists, it must match the source in type.
// If the destination is a directory, the directory must be empty.
//
// Returns a negative error code on failure.
int _lefs_rename(lefs_t *lefs, const char *oldpath, const char *newpath);

// Find info about a file or directory
//
// Fills out the info structure, based on the specified file or directory.
// Returns a negative error code on failure.
int _lefs_stat(lefs_t *lefs, const char *path, struct lefs_info *info);


/// File operations ///

// Open a file
//
// The mode that the file is opened in is determined by the flags, which
// are values from the enum lefs_open_flags that are bitwise-ored together.
//
// Returns a negative error code on failure.
int _lefs_file_open(lefs_t *lefs, lefs_file_t *file,
        const char *path, int flags);

// Open a file with extra configuration
//
// The mode that the file is opened in is determined by the flags, which
// are values from the enum lefs_open_flags that are bitwise-ored together.
//
// The config struct provides additional config options per file as described
// above. The config struct must be allocated while the file is open, and the
// config struct must be zeroed for defaults and backwards compatibility.
//
// Returns a negative error code on failure.
int _lefs_file_opencfg(lefs_t *lefs, lefs_file_t *file,
        const char *path, int flags,
        const struct lefs_file_config *config);

// Close a file
//
// Any pending writes are written out to storage as though
// sync had been called and releases any allocated resources.
//
// Returns a negative error code on failure.
int _lefs_file_close(lefs_t *lefs, lefs_file_t *file);

// Synchronize a file on storage
//
// Any pending writes are written out to storage.
// Returns a negative error code on failure.
int _lefs_file_sync(lefs_t *lefs, lefs_file_t *file);

// Read data from file
//
// Takes a buffer and size indicating where to store the read data.
// Returns the number of bytes read, or a negative error code on failure.
lefs_ssize_t _lefs_file_read(lefs_t *lefs, lefs_file_t *file,
        void *buffer, lefs_size_t size);

// Write data to file
//
// Takes a buffer and size indicating the data to write. The file will not
// actually be updated on the storage until either sync or close is called.
//
// Returns the number of bytes written, or a negative error code on failure.
lefs_ssize_t _lefs_file_write(lefs_t *lefs, lefs_file_t *file,
        const void *buffer, lefs_size_t size);

// Change the position of the file
//
// The change in position is determined by the offset and whence flag.
// Returns the old position of the file, or a negative error code on failure.
lefs_soff_t _lefs_file_seek(lefs_t *lefs, lefs_file_t *file,
        lefs_soff_t off, int whence);

// Truncates the size of the file to the specified size
//
// Returns a negative error code on failure.
int _lefs_file_truncate(lefs_t *lefs, lefs_file_t *file, lefs_off_t size);

// Return the position of the file
//
// Equivalent to _lefs_file_seek(lefs, file, 0, LEFS_SEEK_CUR)
// Returns the position of the file, or a negative error code on failure.
lefs_soff_t _lefs_file_tell(lefs_t *lefs, lefs_file_t *file);

// Change the position of the file to the beginning of the file
//
// Equivalent to _lefs_file_seek(lefs, file, 0, LEFS_SEEK_CUR)
// Returns a negative error code on failure.
int _lefs_file_rewind(lefs_t *lefs, lefs_file_t *file);

// Return the size of the file
//
// Similar to _lefs_file_seek(lefs, file, 0, LEFS_SEEK_END)
// Returns the size of the file, or a negative error code on failure.
lefs_soff_t _lefs_file_size(lefs_t *lefs, lefs_file_t *file);


/// Directory operations ///

// Create a directory
//
// Returns a negative error code on failure.
int _lefs_mkdir(lefs_t *lefs, const char *path);

// Open a directory
//
// Once open a directory can be used with read to iterate over files.
// Returns a negative error code on failure.
int _lefs_dir_open(lefs_t *lefs, lefs_dir_t *dir, const char *path);

// Close a directory
//
// Releases any allocated resources.
// Returns a negative error code on failure.
int _lefs_dir_close(lefs_t *lefs, lefs_dir_t *dir);

// Read an entry in the directory
//
// Fills out the info structure, based on the specified file or directory.
// Returns a negative error code on failure.
int _lefs_dir_read(lefs_t *lefs, lefs_dir_t *dir, struct lefs_info *info);

// Change the position of the directory
//
// The new off must be a value previous returned from tell and specifies
// an absolute offset in the directory seek.
//
// Returns a negative error code on failure.
int _lefs_dir_seek(lefs_t *lefs, lefs_dir_t *dir, lefs_off_t off);

// Return the position of the directory
//
// The returned offset is only meant to be consumed by seek and may not make
// sense, but does indicate the current position in the directory iteration.
//
// Returns the position of the directory, or a negative error code on failure.
lefs_soff_t _lefs_dir_tell(lefs_t *lefs, lefs_dir_t *dir);

// Change the position of the directory to the beginning of the directory
//
// Returns a negative error code on failure.
int _lefs_dir_rewind(lefs_t *lefs, lefs_dir_t *dir);


/// Miscellaneous littleextfs specific operations ///

// Traverse through all blocks in use by the filesystem
//
// The provided callback will be called with each block address that is
// currently in use by the filesystem. This can be used to determine which
// blocks are in use or how much of the storage is available.
//
// Returns a negative error code on failure.
int _lefs_traverse(lefs_t *lefs, int (*cb)(void*, lefs_block_t), void *data);

// Prunes any recoverable errors that may have occured in the filesystem
//
// Not needed to be called by user unless an operation is interrupted
// but the filesystem is still mounted. This is already called on first
// allocation.
//
// Returns a negative error code on failure.
int _lefs_deorphan(lefs_t *lefs);

#ifdef __cplusplus
} /* extern "C" */

} // nsLittleExtFS namespace
#endif

#endif
