/* Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __PIN_BASED_CEC_H__
#define __PIN_BASED_CEC_H__

#include <stdint.h>

__attribute__((noinline)) void PinBasedCEC_MarkSecret(uint64_t secret,
                                                      uint64_t size) {}

__attribute__((noinline)) void PinBasedCEC_ClearSecret(uint64_t secret,
                                                       uint64_t size) {}

__attribute__((noinline)) void PinBasedCEC_ClearSecrets(void) {}

#endif
