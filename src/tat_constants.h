/* Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if !defined(_TAT_CONSTANTS_H_)
# define _TAT_CONSTANTS_H_

#define TAT_MIN_SIGNED_SHORT  (-32768)
#define TAT_MAX_SIGNED_SHORT   (32767)

#define TAT_MIN_SIGNED_BYTE     (-128)
#define TAT_MAX_SIGNED_BYTE      (127)

#define TAT_MIN_UNSIGNED_SHORT     (0)
#define TAT_MAX_UNSIGNED_SHORT (65535)

#define TAT_MIN_UNSIGNED_BYTE      (0)
#define TAT_MAX_UNSIGNED_BYTE    (255)


#define TAT_BYTES_PER_WORD  2
#define TAT_BYTES_PER_DWORD 4
#define TAT_BYTES_PER_QWORD 8
#define TAT_BYTES_PER_XWORD 16
#define TAT_BYTES_PER_YWORD 32
#define TAT_BYTES_PER_ZWORD 64

#define TAT_MAX_MEMOPS_PER_INST 8
#define TAT_MEMORY_GRANULARITY  8

#endif
