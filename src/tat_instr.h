/* Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if !defined(_TAT_INSTR_H_)
# define _TAT_INSTR_H_

#include "tat_constants.h"
extern "C" {
#include "xed-interface.h"
}
#include <stdio.h>
#include <stdlib.h>
typedef enum {
    TAT_VL_XMM=0,
    TAT_VL_YMM=1,
    TAT_VL_ZMM=2,
    TAT_VL_LAST
} tat_vector_length_t;

typedef enum {
    TAT_FLAG_NONE=0,
    TAT_FLAG_REG=1,
    TAT_FLAG_MEM=2,
    TAT_FLAG_IMM=4,
    TAT_FLAG_SPARSE=8,
    TAT_FLAG_ZERO_REG=16,
    TAT_FLAG_AGEN=32
} tat_ins_flags_t;

typedef enum {
    TAT_OTYPE_OTHER=0,
    TAT_OTYPE_REG=1,
    TAT_OTYPE_MEM=2,
    TAT_OTYPE_IMM=3,
    TAT_OTYPE_RELBR=4,
    TAT_OTYPE_AGEN=5
} tat_operand_type_t;

typedef enum  {
    TAT_OPERAND_NONE = 0,
    TAT_OPERAND_READ = 1,
    TAT_OPERAND_WRITTEN = 2,
    TAT_OPERAND_READ_AND_WRITTEN = 3
} tat_operand_access_t;

#define TAT_INSTR_MAX_REGS_PER_INST 10
#define TAT_INSTR_MAX_OPERANDS_PER_INST 8
#define TAT_INSTR_MAX_REG_PER_MEMOP 2

typedef struct  {

    // The ip of the instruction
    uint64_t pc;

    // Operand counts
    uint32_t operand_count; // Number of operands
    uint32_t reg_operand_count; // Number of register operands
    uint32_t mem_operand_count; // Number of memory operands

    // Flags to define instruction
    uint32_t instruction_flags;

    // Operand characteristics arrays
    tat_operand_type_t operand_type[TAT_INSTR_MAX_OPERANDS_PER_INST];
    tat_operand_access_t operand_access[TAT_INSTR_MAX_OPERANDS_PER_INST];

    // Registers operand data
    REG operand_register[TAT_INSTR_MAX_OPERANDS_PER_INST];
    xed_reg_enum_t operand_xed_register[TAT_INSTR_MAX_OPERANDS_PER_INST];

    // Memory operands data
    uint32_t memops_bytes[TAT_MAX_MEMOPS_PER_INST];
    bool memops_is_write[TAT_MAX_MEMOPS_PER_INST];
    REG base_register[TAT_MAX_MEMOPS_PER_INST];
    REG index_register[TAT_MAX_MEMOPS_PER_INST];
    uint64_t memops_memea[TAT_MAX_MEMOPS_PER_INST];

    // Instruction immediate value
    uint16_t imm0;

    // gather or scatter instructions
    bool    gather_or_scatter;

    // target address for mask based conditional branch
    uint64_t target;
    // fall through address for mask based conditional branch
    uint64_t fallthru;

} tat_instr_t;

void tat_instr_init(tat_instr_t* s);
void tat_instr_print(tat_instr_t* s, FILE* f);
tat_instr_t* tat_instr_alloc();

#endif
