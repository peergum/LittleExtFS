/*
 * Copyright (c) 2018 Particle Industries, Inc.  All rights reserved.
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

#pragma once

#include "LittleExtFS.h"

#include <stdint.h>
#include <stdbool.h>
// #include "platform_config.h"

#ifdef __cplusplus


#include <lefs_util.h>
#include <lefs.h>

using namespace nsLittleExtFS;

extern "C" {
#endif /* __cplusplus */

/* FIXME */
#define FILESYSTEM_PROG_SIZE    (256)
#define FILESYSTEM_READ_SIZE    (256)

#define FILESYSTEM_BLOCK_SIZE   LittleExtFS::getInstance()->getBlockSize()
/* XXX: Using half of the external flash for now */
#define FILESYSTEM_BLOCK_COUNT  LittleExtFS::getInstance()->getNumBlocks()
#define FILESYSTEM_LOOKAHEAD    (128)

/* FIXME */
typedef struct {
    uint16_t version;
    uint32_t size;

    struct lefs_config config;
    lefs_t instance;

    bool state;

#ifdef LEFS_NO_MALLOC
    uint8_t read_buffer[FILESYSTEM_READ_SIZE] __attribute__((aligned(4)));
    uint8_t prog_buffer[FILESYSTEM_PROG_SIZE] __attribute__((aligned(4)));
    uint8_t lookahead_buffer[FILESYSTEM_LOOKAHEAD / 8] __attribute__((aligned(4)));
    uint8_t file_buffer[FILESYSTEM_PROG_SIZE] __attribute__((aligned(4)));
#endif /* LEFS_NO_MALLOC */
} filesystem_t;

int filesystem_mount(filesystem_t* fs);
int filesystem_unmount(filesystem_t* fs);
filesystem_t* filesystem_get_instance(void* reserved);
int filesystem_dump_info(filesystem_t* fs);

int filesystem_lock(filesystem_t* fs);
int filesystem_unlock(filesystem_t* fs);

#ifdef __cplusplus
}

// namespace particle { namespace fs {
namespace nsLittleExtFS {

struct FsLock {
    FsLock(filesystem_t* fs)
            : fs_(fs) {
      lock();
    }

    ~FsLock() {
        unlock();
    }

    void lock() {
        filesystem_lock(fs_);
    }

    void unlock() {
        filesystem_unlock(fs_);
    }

private:
    filesystem_t* fs_;
};

// } } /* particle::fs */
} // RTU namespace

#endif /* __cplusplus */
