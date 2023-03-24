/*
 * Copyright (c) 2019 Particle Industries, Inc.  All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#define HAVE_RENAME 1
#define HAVE_GETTIMEOFDAY 1 
#define HAVE_GETPID 1 
#define HAVE_KILL 1

// FIXME: this is a dirty hack in order for newlib headers to provide prototypes for us
#define _COMPILING_NEWLIB

#include "syscalls_posix.h"

// IMPORANT: this is our own implementation header
#include <errno.h>
#include "filesystem.h"
#include "check.h"
#include "intrusive_list.h"
// #include "scope_guard.h"
// #include "rtc_hal.h"
#ifndef HAVE_RENAME
#include <sys/reent.h>
#endif
#ifndef HAL_PLATFORM_FILE_MAXIMUM_FD
#define HAL_PLATFORM_FILE_MAXIMUM_FD (65535)
#endif // HAL_PLATFORM_FILE_MAXIMUM_FD

namespace {

int lefsErrorToErrno(int err) {
    switch (err) {
        case LEFS_ERR_OK:
            return 0;
        case LEFS_ERR_IO:
            return EIO;
        case LEFS_ERR_NOENT:
            return ENOENT;
        case LEFS_ERR_EXIST:
            return EEXIST;
        case LEFS_ERR_NOTDIR:
            return ENOTDIR;
        case LEFS_ERR_ISDIR:
            return EISDIR;
        case LEFS_ERR_INVAL:
            return EINVAL;
        case LEFS_ERR_NOSPC:
            return ENOSPC;
        case LEFS_ERR_NOMEM:
            return ENOMEM;
        case LEFS_ERR_CORRUPT:
            return EILSEQ;
        default:
            if (err > 0) {
                return 0;
            }
            return err;
    }
}

lefs_whence_flags posixWhenceToLefs(int whence) {
    switch (whence) {
        case SEEK_SET:
            return LEFS_SEEK_SET;
        case SEEK_CUR:
            return LEFS_SEEK_CUR;
        case SEEK_END:
            return LEFS_SEEK_END;
        default:
            return (lefs_whence_flags)whence;
    }
}

int posixOpenFlagsToLefs(int flags) {
    // Returns -1 if unknown flags are encountered

    int lefsFlags = 0;
    if ((flags & O_ACCMODE) == O_RDONLY) {
        lefsFlags |= LEFS_O_RDONLY;
    } else if ((flags & O_ACCMODE) == O_WRONLY) {
        lefsFlags |= LEFS_O_WRONLY;
    } else if ((flags & O_ACCMODE) == O_RDWR) {
        lefsFlags |= LEFS_O_RDWR;
    }

    flags &= ~(O_ACCMODE);

    if (flags & O_CREAT) {
        flags &= ~(O_CREAT);
        lefsFlags |= LEFS_O_CREAT;
    }
    if (flags & O_EXCL) {
        flags &= ~(O_EXCL);
        lefsFlags |= LEFS_O_EXCL;
    }
    if (flags & O_TRUNC) {
        flags &= ~(O_TRUNC);
        lefsFlags |= LEFS_O_TRUNC;
    }
    if (flags & O_APPEND) {
        flags &= ~(O_APPEND);
        lefsFlags |= LEFS_O_APPEND;
    }

    // Unknown flags
    if (flags != 0) {
        return -1;
    }

    return lefsFlags;
}

struct FdEntry {
    FdEntry(const char* pathname, bool isFile) {
        if (isFile) {
            file = new lefs_file_t();
        } else {
            dir = new lefs_dir_t();
        }
        if (pathname) {
            name = strdup(pathname);
        }
    }
    ~FdEntry() {
        if (file) {
            delete file;
        }
        if (dir) {
            delete dir;
        }
        if (dent) {
            delete dent;
        }
        if (name) {
            delete name;
        }
    }
    int fd = -1;

    lefs_file_t* file = nullptr;
    lefs_dir_t* dir = nullptr;
    struct dirent* dent = nullptr;

    char* name = nullptr;

    FdEntry* next = nullptr;
};

class FdMap {
public:
    FdMap() = default;
    ~FdMap() = default;

    FdEntry* get(int fd, bool isFile = true) {
        CHECK_TRUE(fd >= MINIMAL_FD && fd <= MAXIMUM_FD, nullptr);

        for (auto entry = fds_.front(); entry != nullptr; entry = entry->next) {
            if (entry->fd == fd && (isFile ? entry->file != nullptr : entry->dir != nullptr)) {
                return entry;
            }
        }

        return nullptr;
    }

    FdEntry* create(const char* pathname, bool isFile = true) {
        FdEntry* entry = new FdEntry(pathname, isFile);
        CHECK_TRUE(entry, nullptr);

        if (entry->name && (entry->file || entry->dir)) {
            entry->fd = nextFd();
            if (entry->fd >= 0) {
                fds_.pushFront(entry);
                return entry;
            }
        }

        delete entry;
        return nullptr;
    }

    bool remove(int fd) {
        CHECK_TRUE(fd >= MINIMAL_FD && fd <= MAXIMUM_FD, false);

        for (auto entry = fds_.front(), prev = (FdEntry*)nullptr; entry != nullptr; prev = entry, entry = entry->next) {
            if (entry->fd == fd) {
                fds_.pop(entry, prev);
                delete entry;
                return true;
            }
        }

        return false;
    }

    bool remove(FdEntry* entry) {
        auto popped = fds_.pop(entry);
        if (popped) {
            delete popped;
            return true;
        }
        return false;
    }

private:
    static constexpr int MINIMAL_FD = STDERR_FILENO + 1;
    static constexpr int MAXIMUM_FD = HAL_PLATFORM_FILE_MAXIMUM_FD;

    particle::IntrusiveList<FdEntry> fds_;

    int nextFd() {
        for (int i = MINIMAL_FD; i <= MAXIMUM_FD; i++) {
            if (!get(i)) {
                return i;
            }
        }
        return -1;
    }
};

FdMap s_fdMap;

}  // anonymous namespace

#define CHECK_LEFS_ERRNO_VAL(_expr, _val) \
        ({ \
            const auto _ret = _expr; \
            errno = lefsErrorToErrno(_ret); \
            if (_ret < 0) { \
                _LOG_CHECKED_ERROR(_expr, _ret); \
                return _val; \
            } \
            _ret; \
        })

#define CHECK_LEFS_ERRNO(_expr) CHECK_LEFS_ERRNO_VAL(_expr, -1)

namespace nsLittleExtFS {  // particle::fs;

extern "C" {

int lefs_open(const char* pathname, int flags, ... /* arg */) {
  if (!pathname) {
    errno = EINVAL;
    return -1;
  }
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);

  auto entry = s_fdMap.create(pathname);
  if (!entry) {
    errno = ENOMEM;
    return -1;
  }

  NAMED_SCOPE_GUARD(g, { s_fdMap.remove(entry); });

  int lefsFlags = posixOpenFlagsToLefs(flags);
  if (lefsFlags < 0) {
    errno = EINVAL;
    return -1;
  }

  CHECK_LEFS_ERRNO(
      _lefs_file_open(&lefs->instance, entry->file, pathname, lefsFlags));
  g.dismiss();
  return entry->fd;
}

int lefs_write(int fd, const void* buf, size_t count) {
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);

  auto entry = s_fdMap.get(fd);
  if (!entry) {
    errno = EBADF;
    return -1;
  }

  return CHECK_LEFS_ERRNO(
      _lefs_file_write(&lefs->instance, entry->file, buf, count));
}

int lefs_read(int fd, void* buf, size_t count) {
    auto lefs = filesystem_get_instance(nullptr);
    FsLock lk(lefs);

    auto entry = s_fdMap.get(fd);
    if (!entry) {
        errno = EBADF;
        return -1;
    }

    return CHECK_LEFS_ERRNO(_lefs_file_read(&lefs->instance, entry->file, buf, count));
}

int lefs_fstat(int fd,
                                                        struct stat* buf) {
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);

  auto entry = s_fdMap.get(fd);
  if (!entry) {
    errno = EBADF;
    return -1;
  }

  return stat(entry->name, buf);
}

int lefs_close(int fd) {
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);

  auto entry = s_fdMap.get(fd);
  if (!entry) {
    errno = EBADF;
    return -1;
  }

  SCOPE_GUARD({ s_fdMap.remove(entry); });

  CHECK_LEFS_ERRNO(_lefs_file_close(&lefs->instance, entry->file));

  return 0;
}

int lefs_execve(const char* filename, char* const argv[], char* const envp[]) {
  // Not implemented
  errno = ENOSYS;
  return -1;
}

int lefs_fcntl(int fd, int cmd, ... /* arg */) {
    // Not implemented
    errno = ENOSYS;
    return -1;
}

pid_t lefs_fork(void) {
    // Not implemented
    errno = ENOSYS;
    return -1;
}

#ifndef HAVE_GETPID
pid_t lefs_getpid(void) {
    // Always return PID = 1
    return 1;
}
#endif

#ifndef HAVE_GETTIMEOFDAY
int lefs_gettimeofday(struct timeval* tv, void* tz) {
    int r = hal_rtc_get_time(tv, nullptr);
    if (r) {
        errno = EFAULT;
        return -1;
    }
    // tz argument is obsolete
    (void)tz;
    return 0;
}
#endif /* HAVE_GETTIMEOFDAY */

int lefs_isatty(int fd) {
    // We won't have any file descriptors referring to a terminal
    errno = ENOTTY;
    return 0;
}

#ifndef HAVE_KILL
int lefs_kill(pid_t pid, int sig) {
    // Not implemented
    errno = ENOSYS;
    return -1;
}
#endif /* HAVE_KILL */

int lefs_link(const char* oldpath, const char* newpath) {
#ifdef HAVE_RENAME
    // Not implemented, LittleExtFS doesn't support symlinks
    errno = ENOSYS;
    return -1;
#else
    // Nano versions of newlib do not support _rename, instead it's
    // implemented as _link + _unlink.

    // As a workaround we'll temporarily store the oldpath into unused
    // entry in the reentrant struct and will ignore error in _unlink
    // if it maches.
    if (lefs_rename(oldpath, newpath)) {
        return -1;
    }

    auto r = _REENT;

    if (r) {
        if (r->_signal_buf) {
            free(r->_signal_buf);
            r->_signal_buf = nullptr;
        }
        r->_signal_buf = strdup(oldpath);
    }

    return 0;
#endif // HAVE_RENAME
}

int lefs_fsync(int fd) {
    auto lefs = filesystem_get_instance(nullptr);
    FsLock lk(lefs);

    auto entry = s_fdMap.get(fd);
    if (!entry) {
        errno = EBADF;
        return -1;
    }

    CHECK_LEFS_ERRNO(_lefs_file_sync(&lefs->instance, entry->file));

    return 0;
}

off_t lefs_lseek(int fd, off_t offset, int whence) {
    auto lefs = filesystem_get_instance(nullptr);
    FsLock lk(lefs);

    auto entry = s_fdMap.get(fd);
    if (!entry) {
        errno = EBADF;
        return -1;
    }

    return CHECK_LEFS_ERRNO(_lefs_file_seek(&lefs->instance, entry->file, offset, posixWhenceToLefs(whence)));
}

int lefs_mkdir(const char* pathname, mode_t mode) {
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);

  CHECK_LEFS_ERRNO(_lefs_mkdir(&lefs->instance, pathname));
  return 0;
}

void* lefs_sbrk(intptr_t increment) {
  // Not implemented
  errno = ENOSYS;
  return nullptr;
}

int lefs_stat(const char* pathname, struct stat* buf) {
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);

  struct lefs_info info = {};
  CHECK_LEFS_ERRNO(_lefs_stat(&lefs->instance, pathname, &info));

  if (buf) {
    buf->st_size = info.size;
    if (info.type == LEFS_TYPE_REG) {
      buf->st_mode = S_IRWXU | S_IRWXG | S_IRWXO | S_IFREG;
    } else if (info.type == LEFS_TYPE_DIR) {
      buf->st_mode = S_IRWXU | S_IRWXG | S_IRWXO | S_IFDIR;
    }
  }

  return 0;
}

clock_t lefs_times(struct tms* buf) {
  // Not implemented
  errno = ENOSYS;
  return (clock_t)-1;
}

int lefs_unlink(const char* pathname) {
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);

  int ret = _lefs_remove(&lefs->instance, pathname);
  // See explanation in lefs_link()
  if (ret == LEFS_ERR_NOENT) {
#ifndef HAVE_RENAME
        auto r = _REENT;
        if (r && r->_signal_buf && !strcmp(pathname, r->_signal_buf)) {
            free(r->_signal_buf);
            r->_signal_buf = nullptr;
            errno = 0;
            return 0;
        }
#endif
    }
    return CHECK_LEFS_ERRNO(ret);
}

int lefs_rmdir(const char* pathname) { return lefs_unlink(pathname); }

pid_t lefs_wait(int* status) {
  // Not implemented
  errno = ENOSYS;
  return -1;
}

DIR* lefs_opendir(const char* name) {
  if (!name) {
    errno = EINVAL;
    return nullptr;
  }
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);
  
  auto entry = s_fdMap.create(name, false);
  if (!entry) {
    errno = ENOMEM;
    return nullptr;
  }

  NAMED_SCOPE_GUARD(g, { s_fdMap.remove(entry); });

  CHECK_LEFS_ERRNO_VAL(_lefs_dir_open(&lefs->instance, entry->dir, name),
                       nullptr);
  g.dismiss();
  // XXX: simply cast int fd to DIR*
  return (DIR*)entry->fd;
}

struct dirent* lefs_readdir(DIR* dirp) {
  struct dirent* result = nullptr;
  readdir_r(dirp, nullptr, &result);
  return result;
}

long lefs_telldir(DIR* pdir) {
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);

  auto entry = s_fdMap.get((int)pdir, false);
  if (!entry) {
    errno = EBADF;
    return -1;
  }

  return CHECK_LEFS_ERRNO(_lefs_dir_tell(&lefs->instance, entry->dir));
}

void lefs_seekdir(DIR* pdir, long loc) {
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);

  auto entry = s_fdMap.get((int)pdir, false);
  if (!entry) {
    errno = EBADF;
    return;
  }

  _lefs_dir_seek(&lefs->instance, entry->dir, loc);
}

void lefs_rewinddir(DIR* pdir) {
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);

  auto entry = s_fdMap.get((int)pdir, false);
  if (!entry) {
    errno = EBADF;
    return;
  }

  _lefs_dir_rewind(&lefs->instance, entry->dir);
}

int lefs_readdir_r(DIR* pdir, struct dirent* dentry,
                   struct dirent** out_dirent) {
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);

  auto entry = s_fdMap.get((int)pdir, false);
  if (!entry) {
    errno = EBADF;
    return -1;
  }

  struct lefs_info info = {};
  int r = _lefs_dir_read(&lefs->instance, entry->dir, &info);
  if (r <= 0) {
    if (out_dirent) {
      *out_dirent = nullptr;
    }
    errno = lefsErrorToErrno(r);
    return -1;
  }

  size_t dentrySize = offsetof(struct dirent, d_name) + strlen(info.name) + 1;

  if (!dentry) {
    entry->dent = static_cast<struct dirent*>(realloc(entry->dent, dentrySize));
    if (!entry->dent) {
      errno = ENOMEM;
      return -1;
    }
    dentry = entry->dent;
  }
  memset(dentry, 0, dentrySize);
  if (info.type == LEFS_TYPE_REG) {
    dentry->d_type = DT_REG;
  } else if (info.type == LEFS_TYPE_DIR) {
    dentry->d_type = DT_DIR;
  }
  dentry->d_reclen = dentrySize;
  strcpy(dentry->d_name, info.name);
  if (out_dirent) {
    *out_dirent = dentry;
  }
  return 0;
}

int lefs_closedir(DIR* dirp) {
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);

  auto entry = s_fdMap.get((int)dirp, false);
  if (!entry) {
    errno = EBADF;
    return -1;
  }

  SCOPE_GUARD({ s_fdMap.remove(entry); });

  CHECK_LEFS_ERRNO(_lefs_dir_close(&lefs->instance, entry->dir));

  return 0;
}

int lefs_chdir(const char* path) {
  // Not implemented
  errno = ENOSYS;
  return -1;
}

int lefs_fchdir(int fd) {
    // Not implemented
    errno = ENOSYS;
    return -1;
}

char* lefs_getcwd(char* buf, size_t size) {
  if (!buf || size < 2) {
    errno = ERANGE;
    return nullptr;
  }
  // XXX: chdir() is not supported, so always return '/'
  buf[0] = '/';
  buf[1] = '\0';
  return buf;
}

int lefs_rename(const char* oldpath, const char* newpath) {
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);

  CHECK_LEFS_ERRNO(_lefs_rename(&lefs->instance, oldpath, newpath));
  return 0;
}

int lefs_ftruncate(int fd, off_t length) {
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);

  auto entry = s_fdMap.get(fd);
  if (!entry) {
    errno = EBADF;
    return -1;
  }

  return CHECK_LEFS_ERRNO(
      _lefs_file_truncate(&lefs->instance, entry->file, length));
}

int lefs_truncate(const char* path, off_t length) {
  if (!path) {
    errno = EINVAL;
    return -1;
  }
  auto lefs = filesystem_get_instance(nullptr);
  FsLock lk(lefs);

  lefs_file_t f = {};
  CHECK_LEFS_ERRNO(_lefs_file_open(&lefs->instance, &f, path, LEFS_O_WRONLY));
  SCOPE_GUARD({ _lefs_file_close(&lefs->instance, &f); });
  CHECK_LEFS_ERRNO(_lefs_file_truncate(&lefs->instance, &f, length));
  return 0;
}

// Current newlib doesn't implement or handle these, so we manually alias _ to non-_
// DIR* lefs_opendir(const char* name) __attribute__((alias("_lefs_opendir")));
// struct dirent* lefs_readdir(DIR* pdir) __attribute__((alias("_lefs_readdir")));
// long lefs_telldir(DIR* pdir) __attribute__((alias("_lefs_telldir")));;
// void lefs_seekdir(DIR* pdir, long loc) __attribute__((alias("_lefs_seekdir")));
// void lefs_rewinddir(DIR* pdir) __attribute__((alias("_lefs_rewinddir")));
// int lefs_readdir_r(DIR* pdir, struct dirent* entry, struct dirent** out_dirent) __attribute__((alias("_lefs_readdir_r")));
// int lefs_closedir(DIR* pdir) __attribute__((alias("_lefs_closedir")));
// int lefs_chdir(const char* path) __attribute__((alias("_lefs_chdir")));
// int lefs_fchdir(int fd) __attribute__((alias("_lefs_fchdir")));
// int lefs_mkdir(const char* pathname, mode_t mode) __attribute__((alias("_lefs_mkdir")));
// int lefs_fsync(int fd) __attribute__((alias("_lefs_fsync")));

} // extern "C"

}  // namespace nsLittleExtFS