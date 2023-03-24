/*
 * The little filesystem
 *
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "lefs.h"
#include "lefs_util.h"

#include <inttypes.h>

namespace nsLittleExtFS {

/// Caching block device operations ///
static int _lefs_cache_read(lefs_t *lefs, lefs_cache_t *rcache,
        const lefs_cache_t *pcache, lefs_block_t block,
        lefs_off_t off, void *buffer, lefs_size_t size) {
    uint8_t *data = (uint8_t *)buffer;
    LEFS_ASSERT(block < lefs->cfg->block_count);

    while (size > 0) {
        if (pcache && block == pcache->block && off >= pcache->off &&
                off < pcache->off + lefs->cfg->prog_size) {
            // is already in pcache?
            lefs_size_t diff = _lefs_min(size,
                    lefs->cfg->prog_size - (off-pcache->off));
            memcpy(data, &pcache->buffer[off-pcache->off], diff);

            data += diff;
            off += diff;
            size -= diff;
            continue;
        }

        if (block == rcache->block && off >= rcache->off &&
                off < rcache->off + lefs->cfg->read_size) {
            // is already in rcache?
            lefs_size_t diff = _lefs_min(size,
                    lefs->cfg->read_size - (off-rcache->off));
            memcpy(data, &rcache->buffer[off-rcache->off], diff);

            data += diff;
            off += diff;
            size -= diff;
            continue;
        }

        if (off % lefs->cfg->read_size == 0 && size >= lefs->cfg->read_size) {
            // bypass cache?
            lefs_size_t diff = size - (size % lefs->cfg->read_size);
            int err = lefs->cfg->read(lefs->cfg, block, off, data, diff);
            if (err) {
              return err;
            }

            data += diff;
            off += diff;
            size -= diff;
            continue;
        }

        // load to cache, first condition can no longer fail
        rcache->block = block;
        rcache->off = off - (off % lefs->cfg->read_size);
        int err = lefs->cfg->read(lefs->cfg, rcache->block,
                rcache->off, rcache->buffer, lefs->cfg->read_size);
        if (err) {
          return err;
        }
    }

    return 0;
}

static int _lefs_cache_cmp(lefs_t *lefs, lefs_cache_t *rcache,
        const lefs_cache_t *pcache, lefs_block_t block,
        lefs_off_t off, const void *buffer, lefs_size_t size) {
  const uint8_t *data = (const uint8_t *)buffer;

  for (lefs_off_t i = 0; i < size; i++) {
    uint8_t c;
    int err = _lefs_cache_read(lefs, rcache, pcache, block, off + i, &c, 1);
    if (err) {
      return err;
    }

    if (c != data[i]) {
      return false;
    }
    }

    return true;
}

static int _lefs_cache_crc(lefs_t *lefs, lefs_cache_t *rcache,
        const lefs_cache_t *pcache, lefs_block_t block,
        lefs_off_t off, lefs_size_t size, uint32_t *crc) {
    for (lefs_off_t i = 0; i < size; i++) {
        uint8_t c;
        int err = _lefs_cache_read(lefs, rcache, pcache,
                block, off+i, &c, 1);
        if (err) {
            return err;
        }

        _lefs_crc(crc, &c, 1);
    }

    return 0;
}

static inline void _lefs_cache_drop(lefs_t *lefs, lefs_cache_t *rcache) {
    // do not zero, cheaper if cache is readonly or only going to be
    // written with identical data (during relocates)
    (void)lefs;
    rcache->block = 0xffffffff;
}

static inline void _lefs_cache_zero(lefs_t *lefs, lefs_cache_t *pcache) {
    // zero to avoid information leak
    memset(pcache->buffer, 0xff, lefs->cfg->prog_size);
    pcache->block = 0xffffffff;
}

static int _lefs_cache_flush(lefs_t *lefs,
        lefs_cache_t *pcache, lefs_cache_t *rcache) {
    if (pcache->block != 0xffffffff) {
        int err = lefs->cfg->prog(lefs->cfg, pcache->block,
                pcache->off, pcache->buffer, lefs->cfg->prog_size);
        if (err) {
            return err;
        }

        if (rcache) {
            int res = _lefs_cache_cmp(lefs, rcache, NULL, pcache->block,
                    pcache->off, pcache->buffer, lefs->cfg->prog_size);
            if (res < 0) {
                return res;
            }

            if (!res) {
                return LEFS_ERR_CORRUPT;
            }
        }

        _lefs_cache_zero(lefs, pcache);
    }

    return 0;
}

static int _lefs_cache_prog(lefs_t *lefs, lefs_cache_t *pcache,
        lefs_cache_t *rcache, lefs_block_t block,
        lefs_off_t off, const void *buffer, lefs_size_t size) {
    const uint8_t *data = (const uint8_t *)buffer;
    LEFS_ASSERT(block < lefs->cfg->block_count);

    while (size > 0) {
        if (block == pcache->block && off >= pcache->off &&
                off < pcache->off + lefs->cfg->prog_size) {
            // is already in pcache?
            lefs_size_t diff = _lefs_min(size,
                    lefs->cfg->prog_size - (off-pcache->off));
            memcpy(&pcache->buffer[off-pcache->off], data, diff);

            data += diff;
            off += diff;
            size -= diff;

            if (off % lefs->cfg->prog_size == 0) {
                // eagerly flush out pcache if we fill up
                int err = _lefs_cache_flush(lefs, pcache, rcache);
                if (err) {
                    return err;
                }
            }

            continue;
        }

        // pcache must have been flushed, either by programming and
        // entire block or manually flushing the pcache
        LEFS_ASSERT(pcache->block == 0xffffffff);

        if (off % lefs->cfg->prog_size == 0 &&
                size >= lefs->cfg->prog_size) {
            // bypass pcache?
            lefs_size_t diff = size - (size % lefs->cfg->prog_size);
            int err = lefs->cfg->prog(lefs->cfg, block, off, data, diff);
            if (err) {
                return err;
            }

            if (rcache) {
                int res = _lefs_cache_cmp(lefs, rcache, NULL,
                        block, off, data, diff);
                if (res < 0) {
                    return res;
                }

                if (!res) {
                    return LEFS_ERR_CORRUPT;
                }
            }

            data += diff;
            off += diff;
            size -= diff;
            continue;
        }

        // prepare pcache, first condition can no longer fail
        pcache->block = block;
        pcache->off = off - (off % lefs->cfg->prog_size);
    }

    return 0;
}


/// General lefs block device operations ///
static int _lefs_bd_read(lefs_t *lefs, lefs_block_t block,
        lefs_off_t off, void *buffer, lefs_size_t size) {
    // if we ever do more than writes to alternating pairs,
    // this may need to consider pcache
    return _lefs_cache_read(lefs, &lefs->rcache, NULL,
            block, off, buffer, size);
}

static int _lefs_bd_prog(lefs_t *lefs, lefs_block_t block,
        lefs_off_t off, const void *buffer, lefs_size_t size) {
    return _lefs_cache_prog(lefs, &lefs->pcache, NULL,
            block, off, buffer, size);
}

static int _lefs_bd_cmp(lefs_t *lefs, lefs_block_t block,
        lefs_off_t off, const void *buffer, lefs_size_t size) {
    return _lefs_cache_cmp(lefs, &lefs->rcache, NULL, block, off, buffer, size);
}

static int _lefs_bd_crc(lefs_t *lefs, lefs_block_t block,
        lefs_off_t off, lefs_size_t size, uint32_t *crc) {
    return _lefs_cache_crc(lefs, &lefs->rcache, NULL, block, off, size, crc);
}

static int _lefs_bd_erase(lefs_t *lefs, lefs_block_t block) {
    return lefs->cfg->erase(lefs->cfg, block);
}

static int _lefs_bd_sync(lefs_t *lefs) {
    _lefs_cache_drop(lefs, &lefs->rcache);

    int err = _lefs_cache_flush(lefs, &lefs->pcache, NULL);
    if (err) {
        return err;
    }

    return lefs->cfg->sync(lefs->cfg);
}


/// Internal operations predeclared here ///
int _lefs_traverse(lefs_t *lefs, int (*cb)(void*, lefs_block_t), void *data);
static int _lefs_pred(lefs_t *lefs, const lefs_block_t dir[2], lefs_dir_t *pdir);
static int _lefs_parent(lefs_t *lefs, const lefs_block_t dir[2],
        lefs_dir_t *parent, lefs_entry_t *entry);
static int _lefs_moved(lefs_t *lefs, const void *e);
static int _lefs_relocate(lefs_t *lefs,
        const lefs_block_t oldpair[2], const lefs_block_t newpair[2]);
int _lefs_deorphan(lefs_t *lefs);


/// Block allocator ///
static int _lefs_alloc_lookahead(void *p, lefs_block_t block) {
    lefs_t *lefs = (lefs_t *)p;

    lefs_block_t off = ((block - lefs->free.off)
            + lefs->cfg->block_count) % lefs->cfg->block_count;

    if (off < lefs->free.size) {
        lefs->free.buffer[off / 32] |= 1U << (off % 32);
    }

    return 0;
}

static int _lefs_alloc(lefs_t *lefs, lefs_block_t *block) {
    while (true) {
        while (lefs->free.i != lefs->free.size) {
            lefs_block_t off = lefs->free.i;
            lefs->free.i += 1;
            lefs->free.ack -= 1;

            if (!(lefs->free.buffer[off / 32] & (1U << (off % 32)))) {
                // found a free block
                *block = (lefs->free.off + off) % lefs->cfg->block_count;

                // eagerly find next off so an alloc ack can
                // discredit old lookahead blocks
                while (lefs->free.i != lefs->free.size &&
                        (lefs->free.buffer[lefs->free.i / 32]
                            & (1U << (lefs->free.i % 32)))) {
                    lefs->free.i += 1;
                    lefs->free.ack -= 1;
                }

                return 0;
            }
        }

        // check if we have looked at all blocks since last ack
        if (lefs->free.ack == 0) {
            LEFS_WARN("No more free space %" PRIu32,
                    lefs->free.i + lefs->free.off);
            return LEFS_ERR_NOSPC;
        }

        lefs->free.off = (lefs->free.off + lefs->free.size)
                % lefs->cfg->block_count;
        lefs->free.size = _lefs_min(lefs->cfg->lookahead, lefs->free.ack);
        lefs->free.i = 0;

        // find mask of free blocks from tree
        memset(lefs->free.buffer, 0, lefs->cfg->lookahead/8);
        int err = _lefs_traverse(lefs, _lefs_alloc_lookahead, lefs);
        if (err) {
            return err;
        }
    }
}

static void _lefs_alloc_ack(lefs_t *lefs) {
    lefs->free.ack = lefs->cfg->block_count;
}


/// Endian swapping functions ///
static void lefs_dir_fromle32(struct lefs_disk_dir *d) {
    d->rev     = lefs_fromle32(d->rev);
    d->size    = lefs_fromle32(d->size);
    d->tail[0] = lefs_fromle32(d->tail[0]);
    d->tail[1] = lefs_fromle32(d->tail[1]);
}

static void lefs_dir_tole32(struct lefs_disk_dir *d) {
    d->rev     = lefs_tole32(d->rev);
    d->size    = lefs_tole32(d->size);
    d->tail[0] = lefs_tole32(d->tail[0]);
    d->tail[1] = lefs_tole32(d->tail[1]);
}

static void lefs_entry_fromle32(struct lefs_disk_entry *d) {
    d->u.dir[0] = lefs_fromle32(d->u.dir[0]);
    d->u.dir[1] = lefs_fromle32(d->u.dir[1]);
}

static void lefs_entry_tole32(struct lefs_disk_entry *d) {
    d->u.dir[0] = lefs_tole32(d->u.dir[0]);
    d->u.dir[1] = lefs_tole32(d->u.dir[1]);
}

static void lefs_superblock_fromle32(struct lefs_disk_superblock *d) {
    d->root[0]     = lefs_fromle32(d->root[0]);
    d->root[1]     = lefs_fromle32(d->root[1]);
    d->block_size  = lefs_fromle32(d->block_size);
    d->block_count = lefs_fromle32(d->block_count);
    d->version     = lefs_fromle32(d->version);
}

static void lefs_superblock_tole32(struct lefs_disk_superblock *d) {
    d->root[0]     = lefs_tole32(d->root[0]);
    d->root[1]     = lefs_tole32(d->root[1]);
    d->block_size  = lefs_tole32(d->block_size);
    d->block_count = lefs_tole32(d->block_count);
    d->version     = lefs_tole32(d->version);
}


/// Metadata pair and directory operations ///
static inline void _lefs_pairswap(lefs_block_t pair[2]) {
    lefs_block_t t = pair[0];
    pair[0] = pair[1];
    pair[1] = t;
}

static inline bool _lefs_pairisnull(const lefs_block_t pair[2]) {
    return pair[0] == 0xffffffff || pair[1] == 0xffffffff;
}

static inline int _lefs_paircmp(
        const lefs_block_t paira[2],
        const lefs_block_t pairb[2]) {
    return !(paira[0] == pairb[0] || paira[1] == pairb[1] ||
             paira[0] == pairb[1] || paira[1] == pairb[0]);
}

static inline bool _lefs_pairsync(
        const lefs_block_t paira[2],
        const lefs_block_t pairb[2]) {
    return (paira[0] == pairb[0] && paira[1] == pairb[1]) ||
           (paira[0] == pairb[1] && paira[1] == pairb[0]);
}

static inline lefs_size_t _lefs_entry_size(const lefs_entry_t *entry) {
    return 4 + entry->d.elen + entry->d.alen + entry->d.nlen;
}

static int _lefs_dir_alloc(lefs_t *lefs, lefs_dir_t *dir) {
    // allocate pair of dir blocks
    for (int i = 0; i < 2; i++) {
        int err = _lefs_alloc(lefs, &dir->pair[i]);
        if (err) {
            return err;
        }
    }

    // rather than clobbering one of the blocks we just pretend
    // the revision may be valid
    int err = _lefs_bd_read(lefs, dir->pair[0], 0, &dir->d.rev, 4);
    if (err && err != LEFS_ERR_CORRUPT) {
        return err;
    }

    if (err != LEFS_ERR_CORRUPT) {
        dir->d.rev = lefs_fromle32(dir->d.rev);
    }

    // set defaults
    dir->d.rev += 1;
    dir->d.size = sizeof(dir->d)+4;
    dir->d.tail[0] = 0xffffffff;
    dir->d.tail[1] = 0xffffffff;
    dir->off = sizeof(dir->d);

    // don't write out yet, let caller take care of that
    return 0;
}

static int _lefs_dir_fetch(lefs_t *lefs,
        lefs_dir_t *dir, const lefs_block_t pair[2]) {
    // copy out pair, otherwise may be aliasing dir
    const lefs_block_t tpair[2] = {pair[0], pair[1]};
    bool valid = false;

    // check both blocks for the most recent revision
    for (int i = 0; i < 2; i++) {
        struct lefs_disk_dir test;
        int err = _lefs_bd_read(lefs, tpair[i], 0, &test, sizeof(test));
        lefs_dir_fromle32(&test);
        if (err) {
            if (err == LEFS_ERR_CORRUPT) {
              continue;
            }
            return err;
        }

        if (valid && _lefs_scmp(test.rev, dir->d.rev) < 0) {
            continue;
        }

        if ((0x7fffffff & test.size) < sizeof(test)+4 ||
            (0x7fffffff & test.size) > lefs->cfg->block_size) {
            continue;
        }

        uint32_t crc = 0xffffffff;
        lefs_dir_tole32(&test);
        _lefs_crc(&crc, &test, sizeof(test));
        lefs_dir_fromle32(&test);
        err = _lefs_bd_crc(lefs, tpair[i], sizeof(test),
                (0x7fffffff & test.size) - sizeof(test), &crc);
        if (err) {
            if (err == LEFS_ERR_CORRUPT) {
              continue;
            }
            return err;
        }

        if (crc != 0) {
            continue;
        }

        valid = true;

        // setup dir in case it's valid
        dir->pair[0] = tpair[(i+0) % 2];
        dir->pair[1] = tpair[(i+1) % 2];
        dir->off = sizeof(dir->d);
        dir->d = test;
    }

    if (!valid) {
        LEFS_ERROR("Corrupted dir pair at %" PRIu32 " %" PRIu32 ,
                tpair[0], tpair[1]);
        return LEFS_ERR_CORRUPT;
    }

    return 0;
}

struct lefs_region {
    lefs_off_t oldoff;
    lefs_size_t oldlen;
    const void *newdata;
    lefs_size_t newlen;
};

static int _lefs_dir_commit(lefs_t *lefs, lefs_dir_t *dir,
        const struct lefs_region *regions, int count) {
    // increment revision count
    dir->d.rev += 1;

    // keep pairs in order such that pair[0] is most recent
    _lefs_pairswap(dir->pair);
    for (int i = 0; i < count; i++) {
        dir->d.size += regions[i].newlen - regions[i].oldlen;
    }

    const lefs_block_t oldpair[2] = {dir->pair[0], dir->pair[1]};
    bool relocated = false;

    while (true) {
        if (true) {
            int err = _lefs_bd_erase(lefs, dir->pair[0]);
            if (err) {
                if (err == LEFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            uint32_t crc = 0xffffffff;
            lefs_dir_tole32(&dir->d);
            _lefs_crc(&crc, &dir->d, sizeof(dir->d));
            err = _lefs_bd_prog(lefs, dir->pair[0], 0, &dir->d, sizeof(dir->d));
            lefs_dir_fromle32(&dir->d);
            if (err) {
                if (err == LEFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            int i = 0;
            lefs_off_t oldoff = sizeof(dir->d);
            lefs_off_t newoff = sizeof(dir->d);
            while (newoff < (0x7fffffff & dir->d.size)-4) {
                if (i < count && regions[i].oldoff == oldoff) {
                    _lefs_crc(&crc, regions[i].newdata, regions[i].newlen);
                    err = _lefs_bd_prog(lefs, dir->pair[0],
                            newoff, regions[i].newdata, regions[i].newlen);
                    if (err) {
                        if (err == LEFS_ERR_CORRUPT) {
                            goto relocate;
                        }
                        return err;
                    }

                    oldoff += regions[i].oldlen;
                    newoff += regions[i].newlen;
                    i += 1;
                } else {
                    uint8_t data;
                    err = _lefs_bd_read(lefs, oldpair[1], oldoff, &data, 1);
                    if (err) {
                        return err;
                    }

                    _lefs_crc(&crc, &data, 1);
                    err = _lefs_bd_prog(lefs, dir->pair[0], newoff, &data, 1);
                    if (err) {
                        if (err == LEFS_ERR_CORRUPT) {
                            goto relocate;
                        }
                        return err;
                    }

                    oldoff += 1;
                    newoff += 1;
                }
            }

            crc = lefs_tole32(crc);
            err = _lefs_bd_prog(lefs, dir->pair[0], newoff, &crc, 4);
            crc = lefs_fromle32(crc);
            if (err) {
                if (err == LEFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            err = _lefs_bd_sync(lefs);
            if (err) {
                if (err == LEFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            // successful commit, check checksum to make sure
            uint32_t ncrc = 0xffffffff;
            err = _lefs_bd_crc(lefs, dir->pair[0], 0,
                    (0x7fffffff & dir->d.size)-4, &ncrc);
            if (err) {
                return err;
            }

            if (ncrc != crc) {
                goto relocate;
            }
        }

        break;
relocate:
        //commit was corrupted
        LEFS_DEBUG("Bad block at %" PRIu32, dir->pair[0]);

        // drop caches and prepare to relocate block
        relocated = true;
        _lefs_cache_drop(lefs, &lefs->pcache);

        // can't relocate superblock, filesystem is now frozen
        if (_lefs_paircmp(oldpair, (const lefs_block_t[2]){0, 1}) == 0) {
            LEFS_WARN("Superblock %" PRIu32 " has become unwritable",
                    oldpair[0]);
            return LEFS_ERR_CORRUPT;
        }

        // relocate half of pair
        int err = _lefs_alloc(lefs, &dir->pair[0]);
        if (err) {
            return err;
        }
    }

    if (relocated) {
        // update references if we relocated
        LEFS_DEBUG("Relocating %" PRIu32 " %" PRIu32 " to %" PRIu32 " %" PRIu32,
                oldpair[0], oldpair[1], dir->pair[0], dir->pair[1]);
        int err = _lefs_relocate(lefs, oldpair, dir->pair);
        if (err) {
            return err;
        }
    }

    // shift over any directories that are affected
    for (lefs_dir_t *d = lefs->dirs; d; d = d->next) {
        if (_lefs_paircmp(d->pair, dir->pair) == 0) {
            d->pair[0] = dir->pair[0];
            d->pair[1] = dir->pair[1];
        }
    }

    return 0;
}

static int _lefs_dir_update(lefs_t *lefs, lefs_dir_t *dir,
        lefs_entry_t *entry, const void *data) {
    lefs_entry_tole32(&entry->d);
    struct lefs_region region[] = {
        {entry->off, sizeof(entry->d), &entry->d, sizeof(entry->d)},
        {entry->off + sizeof(entry->d), entry->d.nlen, data, entry->d.nlen}};
    int err = _lefs_dir_commit(
        lefs, dir,
        region,
        data ? 2 : 1);
    lefs_entry_fromle32(&entry->d);
    return err;
}

static int _lefs_dir_append(lefs_t *lefs, lefs_dir_t *dir,
        lefs_entry_t *entry, const void *data) {
    // check if we fit, if top bit is set we do not and move on
    while (true) {
        if (dir->d.size + _lefs_entry_size(entry) <= lefs->cfg->block_size) {
            entry->off = dir->d.size - 4;

            lefs_entry_tole32(&entry->d);
            struct lefs_region region[] = {
                {entry->off, 0, &entry->d, sizeof(entry->d)},
                {entry->off, 0, data, entry->d.nlen}};
            int err = _lefs_dir_commit(lefs, dir, region, 2);
            lefs_entry_fromle32(&entry->d);
            return err;
        }

        // we need to allocate a new dir block
        if (!(0x80000000 & dir->d.size)) {
            lefs_dir_t olddir = *dir;
            int err = _lefs_dir_alloc(lefs, dir);
            if (err) {
                return err;
            }

            dir->d.tail[0] = olddir.d.tail[0];
            dir->d.tail[1] = olddir.d.tail[1];
            entry->off = dir->d.size - 4;
            lefs_entry_tole32(&entry->d);
            struct lefs_region region[] = {
                {entry->off, 0, &entry->d, sizeof(entry->d)},
                {entry->off, 0, data, entry->d.nlen}};
            err = _lefs_dir_commit(lefs, dir, region, 2);
            lefs_entry_fromle32(&entry->d);
            if (err) {
                return err;
            }

            olddir.d.size |= 0x80000000;
            olddir.d.tail[0] = dir->pair[0];
            olddir.d.tail[1] = dir->pair[1];
            return _lefs_dir_commit(lefs, &olddir, NULL, 0);
        }

        int err = _lefs_dir_fetch(lefs, dir, dir->d.tail);
        if (err) {
            return err;
        }
    }
}

static int _lefs_dir_remove(lefs_t *lefs, lefs_dir_t *dir, lefs_entry_t *entry) {
    // check if we should just drop the directory block
    if ((dir->d.size & 0x7fffffff) == sizeof(dir->d)+4
            + _lefs_entry_size(entry)) {
        lefs_dir_t pdir;
        int res = _lefs_pred(lefs, dir->pair, &pdir);
        if (res < 0) {
            return res;
        }

        if (pdir.d.size & 0x80000000) {
            pdir.d.size &= dir->d.size | 0x7fffffff;
            pdir.d.tail[0] = dir->d.tail[0];
            pdir.d.tail[1] = dir->d.tail[1];
            return _lefs_dir_commit(lefs, &pdir, NULL, 0);
        }
    }

    // shift out the entry
    struct lefs_region region[] = {
        {entry->off, _lefs_entry_size(entry), NULL, 0},
    };
    int err = _lefs_dir_commit(lefs, dir, region, 1);
    if (err) {
        return err;
    }

    // shift over any files/directories that are affected
    for (lefs_file_t *f = lefs->files; f; f = f->next) {
        if (_lefs_paircmp(f->pair, dir->pair) == 0) {
            if (f->poff == entry->off) {
                f->pair[0] = 0xffffffff;
                f->pair[1] = 0xffffffff;
            } else if (f->poff > entry->off) {
                f->poff -= _lefs_entry_size(entry);
            }
        }
    }

    for (lefs_dir_t *d = lefs->dirs; d; d = d->next) {
        if (_lefs_paircmp(d->pair, dir->pair) == 0) {
            if (d->off > entry->off) {
                d->off -= _lefs_entry_size(entry);
                d->pos -= _lefs_entry_size(entry);
            }
        }
    }

    return 0;
}

static int _lefs_dir_next(lefs_t *lefs, lefs_dir_t *dir, lefs_entry_t *entry) {
    while (dir->off + sizeof(entry->d) > (0x7fffffff & dir->d.size)-4) {
        if (!(0x80000000 & dir->d.size)) {
            entry->off = dir->off;
            return LEFS_ERR_NOENT;
        }

        int err = _lefs_dir_fetch(lefs, dir, dir->d.tail);
        if (err) {
            return err;
        }

        dir->off = sizeof(dir->d);
        dir->pos += sizeof(dir->d) + 4;
    }

    int err = _lefs_bd_read(lefs, dir->pair[0], dir->off,
            &entry->d, sizeof(entry->d));
    lefs_entry_fromle32(&entry->d);
    if (err) {
        return err;
    }

    entry->off = dir->off;
    dir->off += _lefs_entry_size(entry);
    dir->pos += _lefs_entry_size(entry);
    return 0;
}

static int _lefs_dir_find(lefs_t *lefs, lefs_dir_t *dir,
        lefs_entry_t *entry, const char **path) {
    const char *pathname = *path;
    size_t pathlen;
    entry->d.type = LEFS_TYPE_DIR;
    entry->d.elen = sizeof(entry->d) - 4;
    entry->d.alen = 0;
    entry->d.nlen = 0;
    entry->d.u.dir[0] = lefs->root[0];
    entry->d.u.dir[1] = lefs->root[1];

    while (true) {
nextname:
        // skip slashes
        pathname += strspn(pathname, "/");
        pathlen = strcspn(pathname, "/");

        // skip '.' and root '..'
        if ((pathlen == 1 && memcmp(pathname, ".", 1) == 0) ||
            (pathlen == 2 && memcmp(pathname, "..", 2) == 0)) {
            pathname += pathlen;
            goto nextname;
        }

        // skip if matched by '..' in name
        const char *suffix = pathname + pathlen;
        size_t sufflen;
        int depth = 1;
        while (true) {
            suffix += strspn(suffix, "/");
            sufflen = strcspn(suffix, "/");
            if (sufflen == 0) {
                break;
            }

            if (sufflen == 2 && memcmp(suffix, "..", 2) == 0) {
                depth -= 1;
                if (depth == 0) {
                    pathname = suffix + sufflen;
                    goto nextname;
                }
            } else {
                depth += 1;
            }

            suffix += sufflen;
        }

        // found path
        if (pathname[0] == '\0') {
            return 0;
        }

        // update what we've found
        *path = pathname;

        // continue on if we hit a directory
        if (entry->d.type != LEFS_TYPE_DIR) {
            return LEFS_ERR_NOTDIR;
        }

        int err = _lefs_dir_fetch(lefs, dir, entry->d.u.dir);
        if (err) {
            return err;
        }

        // find entry matching name
        while (true) {
            err = _lefs_dir_next(lefs, dir, entry);
            if (err) {
                return err;
            }

            if (((0x7f & entry->d.type) != LEFS_TYPE_REG &&
                 (0x7f & entry->d.type) != LEFS_TYPE_DIR) ||
                entry->d.nlen != pathlen) {
                continue;
            }

            int res = _lefs_bd_cmp(lefs, dir->pair[0],
                    entry->off + 4+entry->d.elen+entry->d.alen,
                    pathname, pathlen);
            if (res < 0) {
                return res;
            }

            // found match
            if (res) {
                break;
            }
        }

        // check that entry has not been moved
        if (!lefs->moving && entry->d.type & 0x80) {
            int moved = _lefs_moved(lefs, &entry->d.u);
            if (moved < 0 || moved) {
                return (moved < 0) ? moved : LEFS_ERR_NOENT;
            }

            entry->d.type &= ~0x80;
        }

        // to next name
        pathname += pathlen;
    }
}


/// Top level directory operations ///
int _lefs_mkdir(lefs_t *lefs, const char *path) {
    // deorphan if we haven't yet, needed at most once after poweron
    if (!lefs->deorphaned) {
        int err = _lefs_deorphan(lefs);
        if (err) {
            return err;
        }
    }

    // fetch parent directory
    lefs_dir_t cwd;
    lefs_entry_t entry;
    int err = _lefs_dir_find(lefs, &cwd, &entry, &path);
    if (err != LEFS_ERR_NOENT || strchr(path, '/') != NULL) {
        return err ? err : LEFS_ERR_EXIST;
    }

    // build up new directory
    _lefs_alloc_ack(lefs);

    lefs_dir_t dir;
    err = _lefs_dir_alloc(lefs, &dir);
    if (err) {
        return err;
    }
    dir.d.tail[0] = cwd.d.tail[0];
    dir.d.tail[1] = cwd.d.tail[1];

    err = _lefs_dir_commit(lefs, &dir, NULL, 0);
    if (err) {
        return err;
    }

    entry.d.type = LEFS_TYPE_DIR;
    entry.d.elen = sizeof(entry.d) - 4;
    entry.d.alen = 0;
    entry.d.nlen = strlen(path);
    entry.d.u.dir[0] = dir.pair[0];
    entry.d.u.dir[1] = dir.pair[1];

    cwd.d.tail[0] = dir.pair[0];
    cwd.d.tail[1] = dir.pair[1];

    err = _lefs_dir_append(lefs, &cwd, &entry, path);
    if (err) {
        return err;
    }

    _lefs_alloc_ack(lefs);
    return 0;
}

int _lefs_dir_open(lefs_t *lefs, lefs_dir_t *dir, const char *path) {
    dir->pair[0] = lefs->root[0];
    dir->pair[1] = lefs->root[1];

    lefs_entry_t entry;
    int err = _lefs_dir_find(lefs, dir, &entry, &path);
    if (err) {
        return err;
    } else if (entry.d.type != LEFS_TYPE_DIR) {
        return LEFS_ERR_NOTDIR;
    }

    err = _lefs_dir_fetch(lefs, dir, entry.d.u.dir);
    if (err) {
        return err;
    }

    // setup head dir
    // special offset for '.' and '..'
    dir->head[0] = dir->pair[0];
    dir->head[1] = dir->pair[1];
    dir->pos = sizeof(dir->d) - 2;
    dir->off = sizeof(dir->d);

    // add to list of directories
    dir->next = lefs->dirs;
    lefs->dirs = dir;

    return 0;
}

int _lefs_dir_close(lefs_t *lefs, lefs_dir_t *dir) {
    // remove from list of directories
    for (lefs_dir_t **p = &lefs->dirs; *p; p = &(*p)->next) {
        if (*p == dir) {
            *p = dir->next;
            break;
        }
    }

    return 0;
}

int _lefs_dir_read(lefs_t *lefs, lefs_dir_t *dir, struct lefs_info *info) {
    memset(info, 0, sizeof(*info));

    // special offset for '.' and '..'
    if (dir->pos == sizeof(dir->d) - 2) {
        info->type = LEFS_TYPE_DIR;
        strcpy(info->name, ".");
        dir->pos += 1;
        return 1;
    } else if (dir->pos == sizeof(dir->d) - 1) {
        info->type = LEFS_TYPE_DIR;
        strcpy(info->name, "..");
        dir->pos += 1;
        return 1;
    }

    lefs_entry_t entry;
    while (true) {
        int err = _lefs_dir_next(lefs, dir, &entry);
        if (err) {
            return (err == LEFS_ERR_NOENT) ? 0 : err;
        }

        if ((0x7f & entry.d.type) != LEFS_TYPE_REG &&
            (0x7f & entry.d.type) != LEFS_TYPE_DIR) {
            continue;
        }

        // check that entry has not been moved
        if (entry.d.type & 0x80) {
            int moved = _lefs_moved(lefs, &entry.d.u);
            if (moved < 0) {
                return moved;
            }

            if (moved) {
                continue;
            }

            entry.d.type &= ~0x80;
        }

        break;
    }

    info->type = entry.d.type;
    if (info->type == LEFS_TYPE_REG) {
        info->size = entry.d.u.file.size;
    }

    int err = _lefs_bd_read(lefs, dir->pair[0],
            entry.off + 4+entry.d.elen+entry.d.alen,
            info->name, entry.d.nlen);
    if (err) {
        return err;
    }

    return 1;
}

int _lefs_dir_seek(lefs_t *lefs, lefs_dir_t *dir, lefs_off_t off) {
    // simply walk from head dir
    int err = _lefs_dir_rewind(lefs, dir);
    if (err) {
        return err;
    }
    dir->pos = off;

    while (off > (0x7fffffff & dir->d.size)) {
        off -= 0x7fffffff & dir->d.size;
        if (!(0x80000000 & dir->d.size)) {
            return LEFS_ERR_INVAL;
        }

        err = _lefs_dir_fetch(lefs, dir, dir->d.tail);
        if (err) {
            return err;
        }
    }

    dir->off = off;
    return 0;
}

lefs_soff_t _lefs_dir_tell(lefs_t *lefs, lefs_dir_t *dir) {
    (void)lefs;
    return dir->pos;
}

int _lefs_dir_rewind(lefs_t *lefs, lefs_dir_t *dir) {
    // reload the head dir
    int err = _lefs_dir_fetch(lefs, dir, dir->head);
    if (err) {
        return err;
    }

    dir->pair[0] = dir->head[0];
    dir->pair[1] = dir->head[1];
    dir->pos = sizeof(dir->d) - 2;
    dir->off = sizeof(dir->d);
    return 0;
}


/// File index list operations ///
static int _lefs_ctz_index(lefs_t *lefs, lefs_off_t *off) {
    lefs_off_t size = *off;
    lefs_off_t b = lefs->cfg->block_size - 2*4;
    lefs_off_t i = size / b;
    if (i == 0) {
        return 0;
    }

    i = (size - 4*(_lefs_popc(i-1)+2)) / b;
    *off = size - b*i - 4*_lefs_popc(i);
    return i;
}

static int _lefs_ctz_find(lefs_t *lefs,
        lefs_cache_t *rcache, const lefs_cache_t *pcache,
        lefs_block_t head, lefs_size_t size,
        lefs_size_t pos, lefs_block_t *block, lefs_off_t *off) {
    if (size == 0) {
        *block = 0xffffffff;
        *off = 0;
        return 0;
    }
    lefs_off_t offset = size - 1;
    lefs_off_t current = _lefs_ctz_index(lefs, &offset);
    lefs_off_t target = _lefs_ctz_index(lefs, &pos);

    while (current > target) {
        lefs_size_t skip = _lefs_min(
                lefs_npw2(current-target+1) - 1,
                _lefs_ctz(current));

        int err = _lefs_cache_read(lefs, rcache, pcache, head, 4*skip, &head, 4);
        head = lefs_fromle32(head);
        if (err) {
            return err;
        }

        LEFS_ASSERT(head >= 2 && head <= lefs->cfg->block_count);
        current -= 1 << skip;
    }

    *block = head;
    *off = pos;
    return 0;
}

static int _lefs_ctz_extend(lefs_t *lefs,
        lefs_cache_t *rcache, lefs_cache_t *pcache,
        lefs_block_t head, lefs_size_t size,
        lefs_block_t *block, lefs_off_t *off) {
    while (true) {
        // go ahead and grab a block
        lefs_block_t nblock;
        int err = _lefs_alloc(lefs, &nblock);
        if (err) {
            return err;
        }
        LEFS_ASSERT(nblock >= 2 && nblock <= lefs->cfg->block_count);

        if (true) {
            err = _lefs_bd_erase(lefs, nblock);
            if (err) {
                if (err == LEFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            if (size == 0) {
                *block = nblock;
                *off = 0;
                return 0;
            }

            size -= 1;
            lefs_off_t index = _lefs_ctz_index(lefs, &size);
            size += 1;

            // just copy out the last block if it is incomplete
            if (size != lefs->cfg->block_size) {
                for (lefs_off_t i = 0; i < size; i++) {
                    uint8_t data;
                    err = _lefs_cache_read(lefs, rcache, NULL,
                            head, i, &data, 1);
                    if (err) {
                        return err;
                    }

                    err = _lefs_cache_prog(lefs, pcache, rcache,
                            nblock, i, &data, 1);
                    if (err) {
                        if (err == LEFS_ERR_CORRUPT) {
                            goto relocate;
                        }
                        return err;
                    }
                }

                *block = nblock;
                *off = size;
                return 0;
            }

            // append block
            index += 1;
            lefs_size_t skips = _lefs_ctz(index) + 1;

            for (lefs_off_t i = 0; i < skips; i++) {
                head = lefs_tole32(head);
                err = _lefs_cache_prog(lefs, pcache, rcache,
                        nblock, 4*i, &head, 4);
                head = lefs_fromle32(head);
                if (err) {
                    if (err == LEFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }

                if (i != skips-1) {
                    err = _lefs_cache_read(lefs, rcache, NULL,
                            head, 4*i, &head, 4);
                    head = lefs_fromle32(head);
                    if (err) {
                        return err;
                    }
                }

                LEFS_ASSERT(head >= 2 && head <= lefs->cfg->block_count);
            }

            *block = nblock;
            *off = 4*skips;
            return 0;
        }

relocate:
        LEFS_DEBUG("Bad block at %" PRIu32, nblock);

        // just clear cache and try a new block
        _lefs_cache_drop(lefs, &lefs->pcache);
    }
}

static int _lefs_ctz_traverse(lefs_t *lefs,
        lefs_cache_t *rcache, const lefs_cache_t *pcache,
        lefs_block_t head, lefs_size_t size,
        int (*cb)(void*, lefs_block_t), void *data) {
    if (size == 0) {
        return 0;
    }

    lefs_off_t offset = size - 1;
    lefs_off_t index = _lefs_ctz_index(lefs, &offset);

    while (true) {
        int err = cb(data, head);
        if (err) {
            return err;
        }

        if (index == 0) {
            return 0;
        }

        lefs_block_t heads[2];
        int count = 2 - (index & 1);
        err = _lefs_cache_read(lefs, rcache, pcache, head, 0, &heads, count*4);
        heads[0] = lefs_fromle32(heads[0]);
        heads[1] = lefs_fromle32(heads[1]);
        if (err) {
            return err;
        }

        for (int i = 0; i < count-1; i++) {
            err = cb(data, heads[i]);
            if (err) {
                return err;
            }
        }

        head = heads[count-1];
        index -= count;
    }
}


/// Top level file operations ///
int _lefs_file_opencfg(lefs_t *lefs, lefs_file_t *file,
        const char *path, int flags,
        const struct lefs_file_config *cfg) {
    // deorphan if we haven't yet, needed at most once after poweron
    if ((flags & 3) != LEFS_O_RDONLY && !lefs->deorphaned) {
        int err = _lefs_deorphan(lefs);
        if (err) {
            return err;
        }
    }

    // allocate entry for file if it doesn't exist
    lefs_dir_t cwd;
    lefs_entry_t entry;
    int err = _lefs_dir_find(lefs, &cwd, &entry, &path);
    if (err && (err != LEFS_ERR_NOENT || strchr(path, '/') != NULL)) {
        return err;
    }

    if (err == LEFS_ERR_NOENT) {
        if (!(flags & LEFS_O_CREAT)) {
            return LEFS_ERR_NOENT;
        }

        // create entry to remember name
        entry.d.type = LEFS_TYPE_REG;
        entry.d.elen = sizeof(entry.d) - 4;
        entry.d.alen = 0;
        entry.d.nlen = strlen(path);
        entry.d.u.file.head = 0xffffffff;
        entry.d.u.file.size = 0;
        err = _lefs_dir_append(lefs, &cwd, &entry, path);
        if (err) {
            return err;
        }
    } else if (entry.d.type == LEFS_TYPE_DIR) {
        return LEFS_ERR_ISDIR;
    } else if (flags & LEFS_O_EXCL) {
        return LEFS_ERR_EXIST;
    }

    // setup file struct
    file->cfg = cfg;
    file->pair[0] = cwd.pair[0];
    file->pair[1] = cwd.pair[1];
    file->poff = entry.off;
    file->head = entry.d.u.file.head;
    file->size = entry.d.u.file.size;
    file->flags = flags;
    file->pos = 0;

    if (flags & LEFS_O_TRUNC) {
        if (file->size != 0) {
            file->flags |= LEFS_F_DIRTY;
        }
        file->head = 0xffffffff;
        file->size = 0;
    }

    // allocate buffer if needed
    file->cache.block = 0xffffffff;
    if (file->cfg && file->cfg->buffer) {
        file->cache.buffer = (uint8_t *)file->cfg->buffer;
    } else if (lefs->cfg->file_buffer) {
        if (lefs->files) {
            // already in use
            return LEFS_ERR_NOMEM;
        }
        file->cache.buffer = (uint8_t *)lefs->cfg->file_buffer;
    } else if ((file->flags & 3) == LEFS_O_RDONLY) {
      file->cache.buffer = (uint8_t *)_lefs_malloc(lefs->cfg->read_size);
      if (!file->cache.buffer) {
        return LEFS_ERR_NOMEM;
        }
    } else {
      file->cache.buffer = (uint8_t *)_lefs_malloc(lefs->cfg->prog_size);
      if (!file->cache.buffer) {
        return LEFS_ERR_NOMEM;
        }
    }

    // zero to avoid information leak
    _lefs_cache_drop(lefs, &file->cache);
    if ((file->flags & 3) != LEFS_O_RDONLY) {
        _lefs_cache_zero(lefs, &file->cache);
    }

    // add to list of files
    file->next = lefs->files;
    lefs->files = file;

    return 0;
}

int _lefs_file_open(lefs_t *lefs, lefs_file_t *file,
        const char *path, int flags) {
    return _lefs_file_opencfg(lefs, file, path, flags, NULL);
}

int _lefs_file_close(lefs_t *lefs, lefs_file_t *file) {
    int err = _lefs_file_sync(lefs, file);

    // remove from list of files
    for (lefs_file_t **p = &lefs->files; *p; p = &(*p)->next) {
        if (*p == file) {
            *p = file->next;
            break;
        }
    }

    // clean up memory
    if (!(file->cfg && file->cfg->buffer) && !lefs->cfg->file_buffer) {
        _lefs_free(file->cache.buffer);
    }

    return err;
}

static int _lefs_file_relocate(lefs_t *lefs, lefs_file_t *file) {
relocate:
    LEFS_DEBUG("Bad block at %" PRIu32, file->block);

    // just relocate what exists into new block
    lefs_block_t nblock;
    int err = _lefs_alloc(lefs, &nblock);
    if (err) {
        return err;
    }

    err = _lefs_bd_erase(lefs, nblock);
    if (err) {
        if (err == LEFS_ERR_CORRUPT) {
            goto relocate;
        }
        return err;
    }

    // either read from dirty cache or disk
    for (lefs_off_t i = 0; i < file->off; i++) {
        uint8_t data;
        err = _lefs_cache_read(lefs, &lefs->rcache, &file->cache,
                file->block, i, &data, 1);
        if (err) {
            return err;
        }

        err = _lefs_cache_prog(lefs, &lefs->pcache, &lefs->rcache,
                nblock, i, &data, 1);
        if (err) {
            if (err == LEFS_ERR_CORRUPT) {
                goto relocate;
            }
            return err;
        }
    }

    // copy over new state of file
    memcpy(file->cache.buffer, lefs->pcache.buffer, lefs->cfg->prog_size);
    file->cache.block = lefs->pcache.block;
    file->cache.off = lefs->pcache.off;
    _lefs_cache_zero(lefs, &lefs->pcache);

    file->block = nblock;
    return 0;
}

static int _lefs_file_flush(lefs_t *lefs, lefs_file_t *file) {
    if (file->flags & LEFS_F_READING) {
        // just drop read cache
        _lefs_cache_drop(lefs, &file->cache);
        file->flags &= ~LEFS_F_READING;
    }

    if (file->flags & LEFS_F_WRITING) {
        lefs_off_t pos = file->pos;

        // copy over anything after current branch
        lefs_file_t orig = {
            .head = file->head,
            .size = file->size,
            .flags = LEFS_O_RDONLY,
            .pos = file->pos,
            .cache = lefs->rcache,
        };
        _lefs_cache_drop(lefs, &lefs->rcache);

        while (file->pos < file->size) {
            // copy over a byte at a time, leave it up to caching
            // to make this efficient
            uint8_t data;
            lefs_ssize_t res = _lefs_file_read(lefs, &orig, &data, 1);
            if (res < 0) {
                return res;
            }

            res = _lefs_file_write(lefs, file, &data, 1);
            if (res < 0) {
                return res;
            }

            // keep our reference to the rcache in sync
            if (lefs->rcache.block != 0xffffffff) {
                _lefs_cache_drop(lefs, &orig.cache);
                _lefs_cache_drop(lefs, &lefs->rcache);
            }
        }

        // write out what we have
        while (true) {
            int err = _lefs_cache_flush(lefs, &file->cache, &lefs->rcache);
            if (err) {
                if (err == LEFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            break;
relocate:
            err = _lefs_file_relocate(lefs, file);
            if (err) {
                return err;
            }
        }

        // actual file updates
        file->head = file->block;
        file->size = file->pos;
        file->flags &= ~LEFS_F_WRITING;
        file->flags |= LEFS_F_DIRTY;

        file->pos = pos;
    }

    return 0;
}

int _lefs_file_sync(lefs_t *lefs, lefs_file_t *file) {
    int err = _lefs_file_flush(lefs, file);
    if (err) {
        return err;
    }

    if ((file->flags & LEFS_F_DIRTY) &&
            !(file->flags & LEFS_F_ERRED) &&
            !_lefs_pairisnull(file->pair)) {
        // update dir entry
        lefs_dir_t cwd;
        err = _lefs_dir_fetch(lefs, &cwd, file->pair);
        if (err) {
            return err;
        }

        lefs_entry_t entry = {.off = file->poff};
        err = _lefs_bd_read(lefs, cwd.pair[0], entry.off,
                &entry.d, sizeof(entry.d));
        lefs_entry_fromle32(&entry.d);
        if (err) {
            return err;
        }

        LEFS_ASSERT(entry.d.type == LEFS_TYPE_REG);
        entry.d.u.file.head = file->head;
        entry.d.u.file.size = file->size;

        err = _lefs_dir_update(lefs, &cwd, &entry, NULL);
        if (err) {
            return err;
        }

        file->flags &= ~LEFS_F_DIRTY;
    }

    return 0;
}

lefs_ssize_t _lefs_file_read(lefs_t *lefs, lefs_file_t *file,
        void *buffer, lefs_size_t size) {
    uint8_t *data = (uint8_t *)buffer;
    lefs_size_t nsize = size;

    if ((file->flags & 3) == LEFS_O_WRONLY) {
        return LEFS_ERR_BADF;
    }

    if (file->flags & LEFS_F_WRITING) {
        // flush out any writes
        int err = _lefs_file_flush(lefs, file);
        if (err) {
            return err;
        }
    }

    if (file->pos >= file->size) {
        // eof if past end
        return 0;
    }

    size = _lefs_min(size, file->size - file->pos);
    nsize = size;

    while (nsize > 0) {
        // check if we need a new block
        if (!(file->flags & LEFS_F_READING) ||
                file->off == lefs->cfg->block_size) {
            int err = _lefs_ctz_find(lefs, &file->cache, NULL,
                    file->head, file->size,
                    file->pos, &file->block, &file->off);
            if (err) {
                return err;
            }

            file->flags |= LEFS_F_READING;
        }

        // read as much as we can in current block
        lefs_size_t diff = _lefs_min(nsize, lefs->cfg->block_size - file->off);
        int err = _lefs_cache_read(lefs, &file->cache, NULL,
                file->block, file->off, data, diff);
        if (err) {
            return err;
        }

        file->pos += diff;
        file->off += diff;
        data += diff;
        nsize -= diff;
    }

    return size;
}

lefs_ssize_t _lefs_file_write(lefs_t *lefs, lefs_file_t *file,
        const void *buffer, lefs_size_t size) {
    const uint8_t *data = (const uint8_t *)buffer;
    lefs_size_t nsize = size;

    if ((file->flags & 3) == LEFS_O_RDONLY) {
        return LEFS_ERR_BADF;
    }

    if (file->flags & LEFS_F_READING) {
        // drop any reads
        int err = _lefs_file_flush(lefs, file);
        if (err) {
            return err;
        }
    }

    if ((file->flags & LEFS_O_APPEND) && file->pos < file->size) {
        file->pos = file->size;
    }

    if (file->pos + size > LEFS_FILE_MAX) {
        // larger than file limit?
        return LEFS_ERR_FBIG;
    }

    if (!(file->flags & LEFS_F_WRITING) && file->pos > file->size) {
        // fill with zeros
        lefs_off_t pos = file->pos;
        file->pos = file->size;

        while (file->pos < pos) {
          uint8_t buffer = 0;
          lefs_ssize_t res = _lefs_file_write(lefs, file, &buffer, 1);
          if (res < 0) {
            return res;
            }
        }
    }

    while (nsize > 0) {
        // check if we need a new block
        if (!(file->flags & LEFS_F_WRITING) ||
                file->off == lefs->cfg->block_size) {
            if (!(file->flags & LEFS_F_WRITING) && file->pos > 0) {
                // find out which block we're extending from
                int err = _lefs_ctz_find(lefs, &file->cache, NULL,
                        file->head, file->size,
                        file->pos-1, &file->block, &file->off);
                if (err) {
                    file->flags |= LEFS_F_ERRED;
                    return err;
                }

                // mark cache as dirty since we may have read data into it
                _lefs_cache_zero(lefs, &file->cache);
            }

            // extend file with new blocks
            _lefs_alloc_ack(lefs);
            int err = _lefs_ctz_extend(lefs, &lefs->rcache, &file->cache,
                    file->block, file->pos,
                    &file->block, &file->off);
            if (err) {
                file->flags |= LEFS_F_ERRED;
                return err;
            }

            file->flags |= LEFS_F_WRITING;
        }

        // program as much as we can in current block
        lefs_size_t diff = _lefs_min(nsize, lefs->cfg->block_size - file->off);
        while (true) {
            int err = _lefs_cache_prog(lefs, &file->cache, &lefs->rcache,
                    file->block, file->off, data, diff);
            if (err) {
                if (err == LEFS_ERR_CORRUPT) {
                    goto relocate;
                }
                file->flags |= LEFS_F_ERRED;
                return err;
            }

            break;
relocate:
            err = _lefs_file_relocate(lefs, file);
            if (err) {
                file->flags |= LEFS_F_ERRED;
                return err;
            }
        }

        file->pos += diff;
        file->off += diff;
        data += diff;
        nsize -= diff;

        _lefs_alloc_ack(lefs);
    }

    file->flags &= ~LEFS_F_ERRED;
    return size;
}

lefs_soff_t _lefs_file_seek(lefs_t *lefs, lefs_file_t *file,
        lefs_soff_t off, int whence) {
    // write out everything beforehand, may be noop if rdonly
    int err = _lefs_file_flush(lefs, file);
    if (err) {
        return err;
    }

    // find new pos
    lefs_soff_t npos = file->pos;
    if (whence == LEFS_SEEK_SET) {
        npos = off;
    } else if (whence == LEFS_SEEK_CUR) {
        npos = file->pos + off;
    } else if (whence == LEFS_SEEK_END) {
        npos = file->size + off;
    }

    if (npos < 0 || npos > LEFS_FILE_MAX) {
        // file position out of range
        return LEFS_ERR_INVAL;
    }

    // update pos
    file->pos = npos;
    return npos;
}

int _lefs_file_truncate(lefs_t *lefs, lefs_file_t *file, lefs_off_t size) {
    if ((file->flags & 3) == LEFS_O_RDONLY) {
        return LEFS_ERR_BADF;
    }

    lefs_off_t oldsize = _lefs_file_size(lefs, file);
    if (size < oldsize) {
        // need to flush since directly changing metadata
        int err = _lefs_file_flush(lefs, file);
        if (err) {
            return err;
        }

        lefs_off_t offset = 0;
        // lookup new head in ctz skip list
        err = _lefs_ctz_find(lefs, &file->cache, NULL,
                file->head, file->size,
                size, &file->head, &offset);
        if (err) {
            return err;
        }

        file->size = size;
        file->flags |= LEFS_F_DIRTY;
    } else if (size > oldsize) {
        lefs_off_t pos = file->pos;

        // flush+seek if not already at end
        if (file->pos != oldsize) {
            int err = _lefs_file_seek(lefs, file, 0, LEFS_SEEK_END);
            if (err < 0) {
                return err;
            }
        }

        // fill with zeros
        uint8_t buffer = 0;
        while (file->pos < size) {
          lefs_ssize_t res = _lefs_file_write(lefs, file, &buffer, 1);
          if (res < 0) {
            return res;
          }
        }

        // restore pos
        int err = _lefs_file_seek(lefs, file, pos, LEFS_SEEK_SET);
        if (err < 0) {
            return err;
        }
    }

    return 0;
}

lefs_soff_t _lefs_file_tell(lefs_t *lefs, lefs_file_t *file) {
    (void)lefs;
    return file->pos;
}

int _lefs_file_rewind(lefs_t *lefs, lefs_file_t *file) {
    lefs_soff_t res = _lefs_file_seek(lefs, file, 0, LEFS_SEEK_SET);
    if (res < 0) {
        return res;
    }

    return 0;
}

lefs_soff_t _lefs_file_size(lefs_t *lefs, lefs_file_t *file) {
    (void)lefs;
    if (file->flags & LEFS_F_WRITING) {
        return _lefs_max(file->pos, file->size);
    } else {
        return file->size;
    }
}


/// General fs operations ///
int _lefs_stat(lefs_t *lefs, const char *path, struct lefs_info *info) {
    lefs_dir_t cwd;
    lefs_entry_t entry;
    int err = _lefs_dir_find(lefs, &cwd, &entry, &path);
    if (err) {
        return err;
    }

    memset(info, 0, sizeof(*info));
    info->type = entry.d.type;
    if (info->type == LEFS_TYPE_REG) {
        info->size = entry.d.u.file.size;
    }

    if (_lefs_paircmp(entry.d.u.dir, lefs->root) == 0) {
        strcpy(info->name, "/");
    } else {
        err = _lefs_bd_read(lefs, cwd.pair[0],
                entry.off + 4+entry.d.elen+entry.d.alen,
                info->name, entry.d.nlen);
        if (err) {
            return err;
        }
    }

    return 0;
}

int _lefs_remove(lefs_t *lefs, const char *path) {
    // deorphan if we haven't yet, needed at most once after poweron
    if (!lefs->deorphaned) {
        int err = _lefs_deorphan(lefs);
        if (err) {
            return err;
        }
    }

    lefs_dir_t cwd;
    lefs_entry_t entry;
    int err = _lefs_dir_find(lefs, &cwd, &entry, &path);
    if (err) {
        return err;
    }

    lefs_dir_t dir;
    if (entry.d.type == LEFS_TYPE_DIR) {
        // must be empty before removal, checking size
        // without masking top bit checks for any case where
        // dir is not empty
        err = _lefs_dir_fetch(lefs, &dir, entry.d.u.dir);
        if (err) {
            return err;
        } else if (dir.d.size != sizeof(dir.d)+4) {
            return LEFS_ERR_NOTEMPTY;
        }
    }

    // remove the entry
    err = _lefs_dir_remove(lefs, &cwd, &entry);
    if (err) {
        return err;
    }

    // if we were a directory, find pred, replace tail
    if (entry.d.type == LEFS_TYPE_DIR) {
        int res = _lefs_pred(lefs, dir.pair, &cwd);
        if (res < 0) {
            return res;
        }

        LEFS_ASSERT(res); // must have pred
        cwd.d.tail[0] = dir.d.tail[0];
        cwd.d.tail[1] = dir.d.tail[1];

        err = _lefs_dir_commit(lefs, &cwd, NULL, 0);
        if (err) {
            return err;
        }
    }

    return 0;
}

int _lefs_rename(lefs_t *lefs, const char *oldpath, const char *newpath) {
    // deorphan if we haven't yet, needed at most once after poweron
    if (!lefs->deorphaned) {
        int err = _lefs_deorphan(lefs);
        if (err) {
            return err;
        }
    }

    // find old entry
    lefs_dir_t oldcwd;
    lefs_entry_t oldentry;
    // const char **pOldPath = &oldpath
    int err = _lefs_dir_find(lefs, &oldcwd, &oldentry, &oldpath);
    if (err) {
        return err;
    }

    // mark as moving
    oldentry.d.type |= 0x80;
    err = _lefs_dir_update(lefs, &oldcwd, &oldentry, NULL);
    if (err) {
        return err;
    }

    // allocate new entry
    lefs_dir_t newcwd;
    lefs_entry_t preventry;
    err = _lefs_dir_find(lefs, &newcwd, &preventry, &newpath);
    if (err && (err != LEFS_ERR_NOENT || strchr(newpath, '/') != NULL)) {
        return err;
    }

    // must have same type
    bool prevexists = (err != LEFS_ERR_NOENT);
    if (prevexists && preventry.d.type != (0x7f & oldentry.d.type)) {
        return LEFS_ERR_ISDIR;
    }

    lefs_dir_t dir;
    if (prevexists && preventry.d.type == LEFS_TYPE_DIR) {
        // must be empty before removal, checking size
        // without masking top bit checks for any case where
        // dir is not empty
        err = _lefs_dir_fetch(lefs, &dir, preventry.d.u.dir);
        if (err) {
            return err;
        } else if (dir.d.size != sizeof(dir.d)+4) {
            return LEFS_ERR_NOTEMPTY;
        }
    }

    // move to new location
    lefs_entry_t newentry = preventry;
    newentry.d = oldentry.d;
    newentry.d.type &= ~0x80;
    newentry.d.nlen = strlen(newpath);

    if (prevexists) {
        err = _lefs_dir_update(lefs, &newcwd, &newentry, newpath);
        if (err) {
            return err;
        }
    } else {
        err = _lefs_dir_append(lefs, &newcwd, &newentry, newpath);
        if (err) {
            return err;
        }
    }

    // fetch old pair again in case dir block changed
    lefs->moving = true;
    err = _lefs_dir_find(lefs, &oldcwd, &oldentry, &oldpath);
    if (err) {
        return err;
    }
    lefs->moving = false;

    // remove old entry
    err = _lefs_dir_remove(lefs, &oldcwd, &oldentry);
    if (err) {
        return err;
    }

    // if we were a directory, find pred, replace tail
    if (prevexists && preventry.d.type == LEFS_TYPE_DIR) {
        int res = _lefs_pred(lefs, dir.pair, &newcwd);
        if (res < 0) {
            return res;
        }

        LEFS_ASSERT(res); // must have pred
        newcwd.d.tail[0] = dir.d.tail[0];
        newcwd.d.tail[1] = dir.d.tail[1];

        err = _lefs_dir_commit(lefs, &newcwd, NULL, 0);
        if (err) {
            return err;
        }
    }

    return 0;
}


/// Filesystem operations ///
static void _lefs_deinit(lefs_t *lefs) {
    // free allocated memory
    if (!lefs->cfg->read_buffer) {
        _lefs_free(lefs->rcache.buffer);
    }

    if (!lefs->cfg->prog_buffer) {
        _lefs_free(lefs->pcache.buffer);
    }

    if (!lefs->cfg->lookahead_buffer) {
        _lefs_free(lefs->free.buffer);
    }
}

static int _lefs_init(lefs_t *lefs, const struct lefs_config *cfg) {
    lefs->cfg = cfg;

    // setup read cache
    if (lefs->cfg->read_buffer) {
        lefs->rcache.buffer = (uint8_t *)lefs->cfg->read_buffer;
    } else {
      lefs->rcache.buffer = (uint8_t *)_lefs_malloc(lefs->cfg->read_size);
      if (!lefs->rcache.buffer) {
        goto cleanup;
        }
    }

    // setup program cache
    if (lefs->cfg->prog_buffer) {
      lefs->pcache.buffer = (uint8_t *)lefs->cfg->prog_buffer;
    } else {
      lefs->pcache.buffer = (uint8_t *)_lefs_malloc(lefs->cfg->prog_size);
      if (!lefs->pcache.buffer) {
        goto cleanup;
        }
    }

    // zero to avoid information leaks
    _lefs_cache_zero(lefs, &lefs->pcache);
    _lefs_cache_drop(lefs, &lefs->rcache);

    // setup lookahead, round down to nearest 32-bits
    LEFS_ASSERT(lefs->cfg->lookahead % 32 == 0);
    LEFS_ASSERT(lefs->cfg->lookahead > 0);
    if (lefs->cfg->lookahead_buffer) {
      lefs->free.buffer = (uint32_t *)lefs->cfg->lookahead_buffer;
    } else {
      lefs->free.buffer = (uint32_t *)_lefs_malloc(lefs->cfg->lookahead / 8);
      if (!lefs->free.buffer) {
        goto cleanup;
        }
    }

    // check that program and read sizes are multiples of the block size
    LEFS_ASSERT(lefs->cfg->prog_size % lefs->cfg->read_size == 0);
    LEFS_ASSERT(lefs->cfg->block_size % lefs->cfg->prog_size == 0);

    // check that the block size is large enough to fit ctz pointers
    LEFS_ASSERT(4*lefs_npw2(0xffffffff / (lefs->cfg->block_size-2*4))
            <= lefs->cfg->block_size);

    // setup default state
    lefs->root[0] = 0xffffffff;
    lefs->root[1] = 0xffffffff;
    lefs->files = NULL;
    lefs->dirs = NULL;
    lefs->deorphaned = false;
    lefs->moving = false;

    return 0;

cleanup:
    _lefs_deinit(lefs);
    return LEFS_ERR_NOMEM;
}

int _lefs_format(lefs_t *lefs, const struct lefs_config *cfg) {
  int err = 0;
  if (true) {
    err = _lefs_init(lefs, cfg);
    if (err) {
      return err;
    }

    // create free lookahead
    memset(lefs->free.buffer, 0, lefs->cfg->lookahead / 8);
    lefs->free.off = 0;
    lefs->free.size = _lefs_min(lefs->cfg->lookahead, lefs->cfg->block_count);
    lefs->free.i = 0;
    _lefs_alloc_ack(lefs);

    // create superblock dir
    lefs_dir_t superdir;
    err = _lefs_dir_alloc(lefs, &superdir);
    if (err) {
      goto cleanup;
    }

    // write root directory
    lefs_dir_t root;
    err = _lefs_dir_alloc(lefs, &root);
    if (err) {
      goto cleanup;
    }

    err = _lefs_dir_commit(lefs, &root, NULL, 0);
    if (err) {
      goto cleanup;
    }

    lefs->root[0] = root.pair[0];
    lefs->root[1] = root.pair[1];

    // write superblocks

    lefs_superblock_t superblock = {
        .off = sizeof(superdir.d),
        .d = {
        .type = LEFS_TYPE_SUPERBLOCK,
        .elen = sizeof(superblock.d) - sizeof(superblock.d.magic) - 4,
        .nlen = sizeof(superblock.d.magic),
        .root = {lefs->root[0], lefs->root[1]},
        .block_size = lefs->cfg->block_size,
        .block_count = lefs->cfg->block_count,
        .version = LEFS_DISK_VERSION,
        .magic = {'L','t','l','E','x','t','F','S'},
        },
    };
    superdir.d.tail[0] = root.pair[0];
    superdir.d.tail[1] = root.pair[1];
    superdir.d.size = sizeof(superdir.d) + sizeof(superblock.d) + 4;

    // write both pairs to be safe
    lefs_superblock_tole32(&superblock.d);
    bool valid = false;
    struct lefs_region region[] = {{sizeof(superdir.d), sizeof(superblock.d),
                                    &superblock.d, sizeof(superblock.d)}};
    for (int i = 0; i < 2; i++) {
      err = _lefs_dir_commit(
          lefs, &superdir,
          region,
          1);
      if (err && err != LEFS_ERR_CORRUPT) {
        goto cleanup;
      }

      valid = valid || !err;
    }

    if (!valid) {
      err = LEFS_ERR_CORRUPT;
      goto cleanup;
    }

    // sanity check that fetch works
    err = _lefs_dir_fetch(lefs, &superdir, (const lefs_block_t[2]){0, 1});
    if (err) {
      goto cleanup;
    }

    _lefs_alloc_ack(lefs);
    }

cleanup:
    _lefs_deinit(lefs);
    return err;
}

int _lefs_mount(lefs_t *lefs, const struct lefs_config *cfg) {
  int err = 0;
  if (true) {
    err = _lefs_init(lefs, cfg);
    if (err) {
      return err;
    }

    // setup free lookahead
    lefs->free.off = 0;
    lefs->free.size = 0;
    lefs->free.i = 0;
    _lefs_alloc_ack(lefs);

    // load superblock
    lefs_dir_t dir;
    lefs_superblock_t superblock;
    err = _lefs_dir_fetch(lefs, &dir, (const lefs_block_t[2]){0, 1});
    if (err && err != LEFS_ERR_CORRUPT) {
      goto cleanup;
    }

    if (!err) {
      err = _lefs_bd_read(lefs, dir.pair[0], sizeof(dir.d), &superblock.d,
                          sizeof(superblock.d));
      lefs_superblock_fromle32(&superblock.d);
      if (err) {
        Log.error("BD Read ERR");
        goto cleanup;
      }

      lefs->root[0] = superblock.d.root[0];
      lefs->root[1] = superblock.d.root[1];
    }

    if (err || memcmp(superblock.d.magic, "LtlExtFS", 8) != 0) {
      Log.error("Invalid superblock at %d %d", 0, 1);
      err = LEFS_ERR_CORRUPT;
      goto cleanup;
    }

    uint16_t major_version = (0xffff & (superblock.d.version >> 16));
    uint16_t minor_version = (0xffff & (superblock.d.version >> 0));
    if ((major_version != LEFS_DISK_VERSION_MAJOR ||
         minor_version > LEFS_DISK_VERSION_MINOR)) {
      Log.error("Invalid version %d.%d", major_version, minor_version);
      err = LEFS_ERR_INVAL;
      goto cleanup;
    }

    return 0;
    }

cleanup:

    _lefs_deinit(lefs);
    return err;
}

int _lefs_unmount(lefs_t *lefs) {
    _lefs_deinit(lefs);
    return 0;
}


/// LittleExtFS specific operations ///
int _lefs_traverse(lefs_t *lefs, int (*cb)(void*, lefs_block_t), void *data) {
    if (_lefs_pairisnull(lefs->root)) {
        return 0;
    }

    // iterate over metadata pairs
    lefs_dir_t dir;
    lefs_entry_t entry;
    lefs_block_t cwd[2] = {0, 1};

    while (true) {
        for (int i = 0; i < 2; i++) {
            int err = cb(data, cwd[i]);
            if (err) {
                return err;
            }
        }

        int err = _lefs_dir_fetch(lefs, &dir, cwd);
        if (err) {
            return err;
        }

        // iterate over contents
        while (dir.off + sizeof(entry.d) <= (0x7fffffff & dir.d.size)-4) {
            err = _lefs_bd_read(lefs, dir.pair[0], dir.off,
                    &entry.d, sizeof(entry.d));
            lefs_entry_fromle32(&entry.d);
            if (err) {
                return err;
            }

            dir.off += _lefs_entry_size(&entry);
            if ((0x70 & entry.d.type) == (0x70 & LEFS_TYPE_REG)) {
                err = _lefs_ctz_traverse(lefs, &lefs->rcache, NULL,
                        entry.d.u.file.head, entry.d.u.file.size, cb, data);
                if (err) {
                    return err;
                }
            }
        }

        cwd[0] = dir.d.tail[0];
        cwd[1] = dir.d.tail[1];

        if (_lefs_pairisnull(cwd)) {
            break;
        }
    }

    // iterate over any open files
    for (lefs_file_t *f = lefs->files; f; f = f->next) {
        if (f->flags & LEFS_F_DIRTY) {
            int err = _lefs_ctz_traverse(lefs, &lefs->rcache, &f->cache,
                    f->head, f->size, cb, data);
            if (err) {
                return err;
            }
        }

        if (f->flags & LEFS_F_WRITING) {
            int err = _lefs_ctz_traverse(lefs, &lefs->rcache, &f->cache,
                    f->block, f->pos, cb, data);
            if (err) {
                return err;
            }
        }
    }

    return 0;
}

static int _lefs_pred(lefs_t *lefs, const lefs_block_t dir[2], lefs_dir_t *pdir) {
    if (_lefs_pairisnull(lefs->root)) {
        return 0;
    }

    // iterate over all directory directory entries
    int err = _lefs_dir_fetch(lefs, pdir, (const lefs_block_t[2]){0, 1});
    if (err) {
        return err;
    }

    while (!_lefs_pairisnull(pdir->d.tail)) {
        if (_lefs_paircmp(pdir->d.tail, dir) == 0) {
            return true;
        }

        err = _lefs_dir_fetch(lefs, pdir, pdir->d.tail);
        if (err) {
            return err;
        }
    }

    return false;
}

static int _lefs_parent(lefs_t *lefs, const lefs_block_t dir[2],
        lefs_dir_t *parent, lefs_entry_t *entry) {
    if (_lefs_pairisnull(lefs->root)) {
        return 0;
    }

    parent->d.tail[0] = 0;
    parent->d.tail[1] = 1;

    // iterate over all directory directory entries
    while (!_lefs_pairisnull(parent->d.tail)) {
        int err = _lefs_dir_fetch(lefs, parent, parent->d.tail);
        if (err) {
            return err;
        }

        while (true) {
            err = _lefs_dir_next(lefs, parent, entry);
            if (err && err != LEFS_ERR_NOENT) {
                return err;
            }

            if (err == LEFS_ERR_NOENT) {
                break;
            }

            if (((0x70 & entry->d.type) == (0x70 & LEFS_TYPE_DIR)) &&
                 _lefs_paircmp(entry->d.u.dir, dir) == 0) {
                return true;
            }
        }
    }

    return false;
}

static int _lefs_moved(lefs_t *lefs, const void *e) {
    if (_lefs_pairisnull(lefs->root)) {
        return 0;
    }

    // skip superblock
    lefs_dir_t cwd;
    int err = _lefs_dir_fetch(lefs, &cwd, (const lefs_block_t[2]){0, 1});
    if (err) {
        return err;
    }

    // iterate over all directory directory entries
    lefs_entry_t entry;
    while (!_lefs_pairisnull(cwd.d.tail)) {
        err = _lefs_dir_fetch(lefs, &cwd, cwd.d.tail);
        if (err) {
            return err;
        }

        while (true) {
            err = _lefs_dir_next(lefs, &cwd, &entry);
            if (err && err != LEFS_ERR_NOENT) {
                return err;
            }

            if (err == LEFS_ERR_NOENT) {
                break;
            }

            if (!(0x80 & entry.d.type) &&
                 memcmp(&entry.d.u, e, sizeof(entry.d.u)) == 0) {
                return true;
            }
        }
    }

    return false;
}

static int _lefs_relocate(lefs_t *lefs,
        const lefs_block_t oldpair[2], const lefs_block_t newpair[2]) {
    // find parent
    lefs_dir_t parent;
    lefs_entry_t entry;
    int res = _lefs_parent(lefs, oldpair, &parent, &entry);
    if (res < 0) {
        return res;
    }

    if (res) {
        // update disk, this creates a desync
        entry.d.u.dir[0] = newpair[0];
        entry.d.u.dir[1] = newpair[1];

        int err = _lefs_dir_update(lefs, &parent, &entry, NULL);
        if (err) {
            return err;
        }

        // update internal root
        if (_lefs_paircmp(oldpair, lefs->root) == 0) {
            LEFS_DEBUG("Relocating root %" PRIu32 " %" PRIu32,
                    newpair[0], newpair[1]);
            lefs->root[0] = newpair[0];
            lefs->root[1] = newpair[1];
        }

        // clean up bad block, which should now be a desync
        return _lefs_deorphan(lefs);
    }

    // find pred
    res = _lefs_pred(lefs, oldpair, &parent);
    if (res < 0) {
        return res;
    }

    if (res) {
        // just replace bad pair, no desync can occur
        parent.d.tail[0] = newpair[0];
        parent.d.tail[1] = newpair[1];

        return _lefs_dir_commit(lefs, &parent, NULL, 0);
    }

    // couldn't find dir, must be new
    return 0;
}

int _lefs_deorphan(lefs_t *lefs) {
    lefs->deorphaned = true;

    if (_lefs_pairisnull(lefs->root)) {
        return 0;
    }

    lefs_dir_t pdir = {.d = {.size = 0x80000000}};
    lefs_dir_t cwd = {.d = {.tail = {0,1}}};

    // iterate over all directory directory entries
    for (lefs_size_t i = 0; i < lefs->cfg->block_count; i++) {
        if (_lefs_pairisnull(cwd.d.tail)) {
            return 0;
        }

        int err = _lefs_dir_fetch(lefs, &cwd, cwd.d.tail);
        if (err) {
            return err;
        }

        // Avoid infinite loop when tail == pair
        if (_lefs_paircmp(cwd.pair, cwd.d.tail) == 0) {
            return LEFS_ERR_CORRUPT;
        }

        // check head blocks for orphans
        if (!(0x80000000 & pdir.d.size)) {
            // check if we have a parent
            lefs_dir_t parent;
            lefs_entry_t entry;
            int res = _lefs_parent(lefs, pdir.d.tail, &parent, &entry);
            if (res < 0) {
                return res;
            }

            if (!res) {
                // we are an orphan
                LEFS_DEBUG("Found orphan %" PRIu32 " %" PRIu32,
                        pdir.d.tail[0], pdir.d.tail[1]);

                pdir.d.tail[0] = cwd.d.tail[0];
                pdir.d.tail[1] = cwd.d.tail[1];

                err = _lefs_dir_commit(lefs, &pdir, NULL, 0);
                if (err) {
                    return err;
                }

                return 0;
            }

            if (!_lefs_pairsync(entry.d.u.dir, pdir.d.tail)) {
                // we have desynced
                LEFS_DEBUG("Found desync %" PRIu32 " %" PRIu32,
                        entry.d.u.dir[0], entry.d.u.dir[1]);

                pdir.d.tail[0] = entry.d.u.dir[0];
                pdir.d.tail[1] = entry.d.u.dir[1];

                err = _lefs_dir_commit(lefs, &pdir, NULL, 0);
                if (err) {
                    return err;
                }

                return 0;
            }
        }

        // check entries for moves
        lefs_entry_t entry;
        while (true) {
            err = _lefs_dir_next(lefs, &cwd, &entry);
            if (err && err != LEFS_ERR_NOENT) {
                return err;
            }

            if (err == LEFS_ERR_NOENT) {
                break;
            }

            // found moved entry
            if (entry.d.type & 0x80) {
                int moved = _lefs_moved(lefs, &entry.d.u);
                if (moved < 0) {
                    return moved;
                }

                if (moved) {
                    LEFS_DEBUG("Found move %" PRIu32 " %" PRIu32,
                            entry.d.u.dir[0], entry.d.u.dir[1]);
                    err = _lefs_dir_remove(lefs, &cwd, &entry);
                    if (err) {
                        return err;
                    }
                } else {
                    LEFS_DEBUG("Found partial move %" PRIu32 " %" PRIu32,
                            entry.d.u.dir[0], entry.d.u.dir[1]);
                    entry.d.type &= ~0x80;
                    err = _lefs_dir_update(lefs, &cwd, &entry, NULL);
                    if (err) {
                        return err;
                    }
                }
            }
        }

        memcpy(&pdir, &cwd, sizeof(pdir));
    }

    // If we reached here, we have more directory pairs than blocks in the
    // filesystem... So something must be horribly wrong
    return LEFS_ERR_CORRUPT;
}

}