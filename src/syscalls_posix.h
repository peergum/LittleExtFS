/**
 * @file syscalls_posix.h
 * @author Phil Hilger (phil@peergum.com)
 * @brief 
 * @version 0.1
 * @date 2023-03-23
 * 
 * @copyright Copyright (c) 2023, PeerGum
 * 
 */

#ifndef __SYSCALLS_POSIX_H
#define __SYSCALLS_POSIX_H

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dirent.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef __cplusplus
namespace nsLittleExtFS {

extern "C" {
#endif

// external posix-like functions declaration
int lefs_open(const char *pathname, int flags, ... /* arg */);
int lefs_write(int fd, const void *buf, size_t count);
int lefs_read(int fd, void *buf, size_t count);
int lefs_read(int fd, void *buf, size_t count);
int lefs_fstat(int fd, struct stat *buf);
int lefs_close(int fd);
int lefs_execve(const char *filename, char *const argv[], char *const envp[]);
int lefs_fcntl(int fd, int cmd, ... /* arg */);
pid_t lefs_fork(void);
int lefs_isatty(int fd);
int lefs_link(const char *oldpath, const char *newpath);
int lefs_fsync(int fd);
off_t lefs_lseek(int fd, off_t offset, int whence);
int lefs_mkdir(const char *pathname, mode_t mode);
void *lefs_sbrk(intptr_t increment);
int lefs_stat(const char *pathname, struct stat *buf);
clock_t lefs_times(struct tms *buf);
int lefs_unlink(const char *pathname);
int lefs_rmdir(const char *pathname);
pid_t lefs_wait(int *status);
DIR *lefs_opendir(const char *name);
struct dirent *lefs_readdir(DIR *dirp);
long lefs_telldir(DIR *pdir);
void lefs_seekdir(DIR *pdir, long loc);
void lefs_rewinddir(DIR *pdir);
int lefs_readdir_r(DIR *pdir, struct dirent *dentry,
                   struct dirent **out_dirent);
int lefs_closedir(DIR *dirp);
int lefs_chdir(const char *path);
int lefs_fchdir(int fd);
char *lefs_getcwd(char *buf, size_t size);
int lefs_rename(const char *oldpath, const char *newpath);
int lefs_ftruncate(int fd, off_t length);
int lefs_truncate(const char *path, off_t length);

#ifdef __cplusplus
} /* extern "C" */

} // nsLittleExtFS namespace

#endif

#endif // __SYSCALLS_POSIX_H