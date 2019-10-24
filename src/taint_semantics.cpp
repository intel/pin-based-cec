/* Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <cstdint>
#include <iostream>

#include "MyPinTool.h"
#include "pin.H"
#include "taint_semantics.h"
//#include "xed-decoded-inst-api.h"

extern "C" {
#include "xed-interface.h"
}

#include "tat_instr.h"

// Call order for TAT
typedef enum {

  // pre-marshall memory
  TAT_CALL_ORDER_PREMARSHALL = CALL_ORDER_LAST - 10,

  // taint analysis
  TAT_CALL_ORDER_TAINT = CALL_ORDER_LAST - 5,

} tat_call_order_t;

void tat_instr_init(tat_instr_t* s) { memset(s, 0, sizeof(tat_instr_t)); }

tat_instr_t* tat_instr_alloc() {
  tat_instr_t* p = (tat_instr_t*)(malloc(sizeof(tat_instr_t)));
  tat_instr_init(p);
  return p;
}

REG tat_xed_exact_map_to_pin_reg(xed_reg_enum_t r) {
  return INS_XedExactMapToPinReg(r);
}

static xed_reg_enum_t tat_get_largest_enclosing_register(
    xed_reg_enum_t xedreg) {
  return xed_get_largest_enclosing_register(xedreg);
}

/* Function to instrument mem0 components :
 * Get base register and index registers
 * This is done to check if those registers are tainted
 * and caused tainted memory address
 * */
static void tat_instrument_mem_components(tat_instr_t* instr,
                                          xed_decoded_inst_t const* const xedd,
                                          uint32_t memop) {
  // Get base register
  xed_reg_enum_t xed_base = xed_decoded_inst_get_base_reg(xedd, memop);
  if (xed_base == XED_REG_INVALID) {
    instr->base_register[memop] = REG_INVALID();
  } else {
    xed_reg_enum_t fullreg = tat_get_largest_enclosing_register(xed_base);
    instr->base_register[memop] = tat_xed_exact_map_to_pin_reg(fullreg);
  }

  // Get index register
  xed_reg_enum_t xed_index = xed_decoded_inst_get_index_reg(xedd, memop);
  if (xed_index == XED_REG_INVALID) {
    instr->index_register[memop] = REG_INVALID();
  } else {
    xed_reg_enum_t fullreg = tat_get_largest_enclosing_register(xed_index);
    instr->index_register[memop] = tat_xed_exact_map_to_pin_reg(fullreg);
  }
}

// Check if this is zeroing instruction for registers
// like - xor rax,rax
static void tat_instrument_check_if_zero_register(tat_instr_t* instr,
                                                  xed_iclass_enum_t iclass) {
  // Only relevant for registers
  if (instr->instruction_flags != TAT_FLAG_REG) return;

  uint32_t operands_to_compare;

  switch (iclass) {
    case XED_ICLASS_PXOR:
    case XED_ICLASS_XOR:
    case XED_ICLASS_XORPD:
    case XED_ICLASS_XORPS:
      operands_to_compare = 2;
      break;
    case XED_ICLASS_VPXOR:
    case XED_ICLASS_VXORPD:
    case XED_ICLASS_VXORPS:
      operands_to_compare = 3;
      break;
    default:
      // This instruction is not relevant to zeroing register
      return;
  }

  xed_reg_enum_t first_register = instr->operand_xed_register[0];
  for (uint32_t op_ind = 1; op_ind < operands_to_compare; op_ind++) {
    // If those are not exactly the same registers then
    // this is no zeroing register instruction
    if (first_register != instr->operand_xed_register[op_ind]) return;
  }

  // If we got here then
  // all operands are the same then we are zeroing the register
  instr->instruction_flags |= TAT_FLAG_ZERO_REG;
  return;
}

// Get operand access
tat_operand_access_t get_access(const xed_operand_t* operand) {
  // In conditional write we also need to read the register
  if (xed_operand_conditional_write(operand))
    return TAT_OPERAND_READ_AND_WRITTEN;
  else if (xed_operand_read_only(operand))
    return TAT_OPERAND_READ;
  else if (xed_operand_written_only(operand))
    return TAT_OPERAND_WRITTEN;
  else
    return TAT_OPERAND_READ_AND_WRITTEN;
}

// This function instruments the operand of the instruction
void tat_instrument_operand(INS ins, xed_decoded_inst_t const* const xedd,
                            xed_inst_t const* const xedi,
                            uint32_t operand_index, tat_instr_t* instr) {
  const xed_operand_t* operand = xed_inst_operand(xedi, operand_index);
  const xed_operand_enum_t operand_name = xed_operand_name(operand);
  const xed_category_enum_t cat = xed_decoded_inst_get_category(xedd);
  tat_operand_access_t access;

  // Instrument register operands
  if (xed_operand_is_register(operand_name)) {
    xed_reg_enum_t xedreg = xed_decoded_inst_get_reg(xedd, operand_name);
    xed_reg_enum_t fullreg = tat_get_largest_enclosing_register(xedreg);
    xed_reg_class_enum_t reg_class = xed_reg_class(xedreg);

    // Handler pop and push register
    if (fullreg == XED_REG_STACKPOP || fullreg == XED_REG_STACKPUSH) {
      fullreg = XED_REG_RSP;
      access = TAT_OPERAND_READ_AND_WRITTEN;
    }
    // Un-handled register classes
    else if (reg_class == XED_REG_CLASS_PSEUDO ||
             reg_class == XED_REG_CLASS_PSEUDOX87 ||
             reg_class == XED_REG_CLASS_XCR) {
      return;
    }
    // Get operand access
    else {
      access = get_access(operand);
    }

    // Get PIN register
    REG pinreg = tat_xed_exact_map_to_pin_reg(fullreg);

    // Direct branches or calls or Conditional branches can not taint registers
    if ((INS_IsDirectBranch(ins) || INS_IsDirectCall(ins) || cat == XED_CATEGORY_COND_BR) &&
        (access == TAT_OPERAND_WRITTEN ||
         access == TAT_OPERAND_READ_AND_WRITTEN)) {
      return;
    }

    // Set instr fields
    instr->instruction_flags |= TAT_FLAG_REG;
    instr->reg_operand_count++;
    instr->operand_type[operand_index] = TAT_OTYPE_REG;
    instr->operand_access[operand_index] = access;
    instr->operand_register[operand_index] = pinreg;
    instr->operand_xed_register[operand_index] = xedreg;
  }

  // Handle memory operands
  else if (operand_name == XED_OPERAND_MEM0 ||
           operand_name == XED_OPERAND_MEM1) {
    // Set instr fields
    instr->instruction_flags |= TAT_FLAG_MEM;
    instr->operand_type[operand_index] = TAT_OTYPE_MEM;
    // Determine access
    if (xed_decoded_inst_mem_written(xedd, 0) &&
        xed_decoded_inst_mem_read(xedd, 0)) {
      instr->operand_access[operand_index] = TAT_OPERAND_READ_AND_WRITTEN;
    } else if (xed_decoded_inst_mem_written(xedd, 0)) {
      instr->operand_access[operand_index] = TAT_OPERAND_WRITTEN;
    } else if (xed_decoded_inst_mem_read(xedd, 0)) {
      instr->operand_access[operand_index] = TAT_OPERAND_READ;
    } else {
      std::cout << "Illegal access type in memory operand" << std::endl;
      PIN_ExitProcess(1);
    }

    // Determine memop index
    uint32_t memop = 0;
    if (operand_name == XED_OPERAND_MEM1) memop = 1;

    // Set base and index registers
    if (instr->gather_or_scatter) {
      // Support memory operands of gather instructions
      for (memop = 0; memop < instr->mem_operand_count; memop++) {
        tat_instrument_mem_components(instr, xedd, memop);
      }
    } else {
      // Normal memory operand
      tat_instrument_mem_components(instr, xedd, memop);
    }
  }

  // Handle immediate operands
  else if (operand_name == XED_OPERAND_IMM0) {
    const xed_operand_values_t* ov;
    ov = xed_decoded_inst_operands_const(xedd);
    instr->imm0 = (uint16_t)xed_operand_values_get_immediate_uint64(ov);

    // Set instr fields
    instr->instruction_flags |= TAT_FLAG_IMM;
    instr->operand_type[operand_index] = TAT_OTYPE_IMM;
    instr->operand_access[operand_index] = TAT_OPERAND_NONE;
  }

  // Set RELBR operands
  else if (operand_name == XED_OPERAND_RELBR) {
    // Set instr fields
    instr->operand_type[operand_index] = TAT_OTYPE_RELBR;
    instr->operand_access[operand_index] = TAT_OPERAND_NONE;

    // Set fall through and target fields for conditional branches
    instr->fallthru = instr->pc + xed_decoded_inst_get_length(xedd);
    instr->target =
        instr->fallthru + xed_decoded_inst_get_branch_displacement(xedd);
  }

  // We do not need to do anything in base register
  // cause PIN will handle as memory operands
  else if (xed_operand_is_memory_addressing_register(operand_name)) {
  }

  // Handle AGEN operand like in lea instructions
  else if (operand_name == XED_OPERAND_AGEN) {
    // Set instr fields
    instr->instruction_flags |= TAT_FLAG_AGEN;
    instr->operand_type[operand_index] = TAT_OTYPE_AGEN;
    instr->operand_access[operand_index] = TAT_OPERAND_READ;

    // Set base and index registers
    tat_instrument_mem_components(instr, xedd, 0);
  }

  else {
    std::ostringstream os;
    os << "Unhandled operand " << operand_index << " "
       << xed_operand_enum_t2str(operand_name)
       << " in Instruction: " << INS_Disassemble(ins)
       << " memops: " << INS_MemoryOperandCount(ins) << std::endl;
    std::cout << os;
    PIN_ExitProcess(1);
  }
}

// This is the main instrumentation function
void tat_instrument(INS ins, void* v) {
  // Get XED data
  xed_decoded_inst_t const* const xedd = INS_XedDec(ins);
  const xed_inst_t* xedi = xed_decoded_inst_inst(xedd);
  const xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(xedd);
  uint32_t memop_idx;

  // Allocate and initialize instr
  tat_instr_t* instr = tat_instr_alloc();
  instr->pc = INS_Address(ins);
  instr->gather_or_scatter =
      xed_decoded_inst_get_attribute(xedd, XED_ATTRIBUTE_GATHER);

  // Instrument operands
  instr->operand_count = xed_inst_noperands(xedi);
  instr->mem_operand_count = INS_MemoryOperandCount(ins);
  for (uint32_t i = 0; i < instr->operand_count; i++)
    tat_instrument_operand(ins, xedd, xedi, i, instr);

  // Check if this is zeroing instruction for registers
  // like - xor rax,rax
  tat_instrument_check_if_zero_register(instr, iclass);

  // Taint analysis routine
  // Call it only when registers or memory are affected
  if (instr->instruction_flags & (TAT_FLAG_REG | TAT_FLAG_MEM | TAT_FLAG_AGEN)) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)InstructionCanBeTainted,
                     IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER,
                     TAT_CALL_ORDER_TAINT,
                     // IARG_REG_VALUE, virtual_reg_tdata,
                     IARG_END);

    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)AnalyzeInstructionForTaint,
                       IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER,
                       TAT_CALL_ORDER_TAINT,
                       // IARG_REG_VALUE, virtual_reg_tdata,
                       IARG_PTR, instr, IARG_END);
  }

  // Memory taint pre-marshalling
  for (memop_idx = 0; memop_idx < instr->mem_operand_count; memop_idx++) {
    // Update memop data
    instr->memops_bytes[memop_idx] =
        (uint32_t)INS_MemoryOperandSize(ins, memop_idx);
    instr->memops_is_write[memop_idx] =
        INS_MemoryOperandIsWritten(ins, memop_idx);

    // Prepare pre-marshalling for data of memory operands
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)MemoryIsTainted,
                     IARG_FAST_ANALYSIS_CALL, IARG_CALL_ORDER,
                     TAT_CALL_ORDER_PREMARSHALL,
                     // IARG_REG_VALUE, virtual_reg_tdata,
                     IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)PremarshallMemoryOperand,
                       IARG_FAST_ANALYSIS_CALL,
                       // IARG_REG_VALUE, virtual_reg_tdata,
                       IARG_PTR, instr, IARG_UINT32, memop_idx, IARG_MEMORYOP_EA,
                       memop_idx, IARG_CALL_ORDER, TAT_CALL_ORDER_PREMARSHALL,
                       IARG_END);
  }

}

void TaintInstruction(INS ins, void* v) { tat_instrument(ins, v); }
