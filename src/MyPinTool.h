/* Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __MY_PIN_TOOL_H__
#define __MY_PIN_TOOL_H__

#include "pin.H"

#include "tat_instr.h"

ADDRINT PIN_FAST_ANALYSIS_CALL InstructionCanBeTainted();
ADDRINT PIN_FAST_ANALYSIS_CALL MemoryIsTainted();
void PIN_FAST_ANALYSIS_CALL PremarshallMemoryOperand(tat_instr_t* instr,
                                                     uint32_t memop_idx,
                                                     ADDRINT memea);
void PIN_FAST_ANALYSIS_CALL AnalyzeInstructionForTaint(tat_instr_t* instr);

#endif
