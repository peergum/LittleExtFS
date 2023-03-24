/*
 * lefs utility functions
 *
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef LEFS_UTIL_H
#define LEFS_UTIL_H

// Users can override lefs_util.h with their own configuration by defining
// Lefs_CONFIG as a header file to include (-DLEFS_CONFIG=lefs_config.h).
//
// If LEFS_CONFIG is used, none of the default utils will be emitted and must be
// provided by the config file. To start I would suggest copying lefs_util.h and
// modifying as needed.
#ifdef LEFS_CONFIG
#define LEFS_STRINGIZE(x) LEFS_STRINGIZE2(x)
#define LEFS_STRINGIZE2(x) #x
#include LEFS_STRINGIZE(LEFS_CONFIG)
#else

// System includes
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifndef LEFS_NO_MALLOC
#include <stdlib.h>
#endif
#ifndef LEFS_NO_ASSERT
#include <assert.h>
#endif
#if !defined(LEFS_NO_DEBUG) || !defined(LEFS_NO_WARN) || !defined(LEFS_NO_ERROR)
#include <stdio.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif


// Macros, may be replaced by system specific wrappers. Arguments to these
// macros must not have side-effects as the macros can be removed for a smaller
// code footprint

// Logging functions
#ifndef LEFS_NO_DEBUG
#define LEFS_DEBUG(fmt, ...) \
    printf("lefs debug:%d: " fmt "\n", __LINE__, __VA_ARGS__)
#else
#define LEFS_DEBUG(fmt, ...)
#endif

#ifndef LEFS_NO_WARN
#define LEFS_WARN(fmt, ...) \
    printf("lefs warn:%d: " fmt "\n", __LINE__, __VA_ARGS__)
#else
#define LEFS_WARN(fmt, ...)
#endif

#ifndef LEFS_NO_ERROR
#define LEFS_ERROR(fmt, ...) \
    printf("lefs error:%d: " fmt "\n", __LINE__, __VA_ARGS__)
#else
#define LEFS_ERROR(fmt, ...)
#endif

// Runtime assertions
#ifndef LEFS_NO_ASSERT
#define LEFS_ASSERT(test) assert(test)
#else
#define LEFS_ASSERT(test)
#endif


// Builtin functions, these may be replaced by more efficient
// toolchain-specific implementations. LEFS_NO_INTRINSICS falls back to a more
// expensive basic C implementation for debugging purposes

// Min/max functions for unsigned 32-bit numbers
static inline uint32_t _lefs_max(uint32_t a, uint32_t b) {
    return (a > b) ? a : b;
}

static inline uint32_t _lefs_min(uint32_t a, uint32_t b) {
    return (a < b) ? a : b;
}

// Find the next smallest power of 2 less than or equal to a
static inline uint32_t lefs_npw2(uint32_t a) {
#if !defined(LEFS_NO_INTRINSICS) && (defined(__GNUC__) || defined(__CC_ARM))
    return 32 - __builtin_clz(a-1);
#else
    uint32_t r = 0;
    uint32_t s;
    a -= 1;
    s = (a > 0xffff) << 4; a >>= s; r |= s;
    s = (a > 0xff  ) << 3; a >>= s; r |= s;
    s = (a > 0xf   ) << 2; a >>= s; r |= s;
    s = (a > 0x3   ) << 1; a >>= s; r |= s;
    return (r | (a >> 1)) + 1;
#endif
}

// Count the number of trailing binary zeros in a
// _lefs_ctz(0) may be undefined
static inline uint32_t _lefs_ctz(uint32_t a) {
#if !defined(LEFS_NO_INTRINSICS) && defined(__GNUC__)
    return __builtin_ctz(a);
#else
    return lefs_npw2((a & -a) + 1) - 1;
#endif
}

// Count the number of binary ones in a
static inline uint32_t _lefs_popc(uint32_t a) {
#if !defined(LEFS_NO_INTRINSICS) && (defined(__GNUC__) || defined(__CC_ARM))
    return __builtin_popcount(a);
#else
    a = a - ((a >> 1) & 0x55555555);
    a = (a & 0x33333333) + ((a >> 2) & 0x33333333);
    return (((a + (a >> 4)) & 0xf0f0f0f) * 0x1010101) >> 24;
#endif
}

// Find the sequence comparison of a and b, this is the distance
// between a and b ignoring overflow
static inline int _lefs_scmp(uint32_t a, uint32_t b) {
    return (int)(unsigned)(a - b);
}

// Convert from 32-bit little-endian to native order
static inline uint32_t lefs_fromle32(uint32_t a) {
#if !defined(LEFS_NO_INTRINSICS) && ( \
    (defined(  BYTE_ORDER  ) &&   BYTE_ORDER   ==   ORDER_LITTLE_ENDIAN  ) || \
    (defined(__BYTE_ORDER  ) && __BYTE_ORDER   == __ORDER_LITTLE_ENDIAN  ) || \
    (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
    return a;
#elif !defined(LEFS_NO_INTRINSICS) && ( \
    (defined(  BYTE_ORDER  ) &&   BYTE_ORDER   ==   ORDER_BIG_ENDIAN  ) || \
    (defined(__BYTE_ORDER  ) && __BYTE_ORDER   == __ORDER_BIG_ENDIAN  ) || \
    (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__))
    return __builtin_bswap32(a);
#else
    return (((uint8_t*)&a)[0] <<  0) |
           (((uint8_t*)&a)[1] <<  8) |
           (((uint8_t*)&a)[2] << 16) |
           (((uint8_t*)&a)[3] << 24);
#endif
}

// Convert to 32-bit little-endian from native order
static inline uint32_t lefs_tole32(uint32_t a) {
    return lefs_fromle32(a);
}

// Calculate CRC-32 with polynomial = 0x04c11db7
void _lefs_crc(uint32_t *crc, const void *buffer, size_t size);

// Allocate memory, only used if buffers are not provided to littleextfs
static inline void *_lefs_malloc(size_t size) {
#ifndef LEFS_NO_MALLOC
    return malloc(size);
#else
    (void)size;
    return NULL;
#endif
}

// Deallocate memory, only used if buffers are not provided to littleextfs
static inline void _lefs_free(void *p) {
#ifndef LEFS_NO_MALLOC
    free(p);
#else
    (void)p;
#endif
}


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
#endif
