/* Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "taint.h"
#include <stdint.h>
#include <fstream>
#include <iostream>
#include <set>
#include "pin.H"
#include "visit_counter.h"

#include "tat_instr.h"

Taint::Taint(Tracer* _tracer, IpVisitCounter* _ipVisitCounter,
             bool _ignoreRIP) {
  tracer = _tracer;
  ipVisitCounter = _ipVisitCounter;
  ignoreRIP = _ignoreRIP;
}

Taint::~Taint() {}

bool Taint::regIsTainted(REG reg) {
  std::set<REG>::iterator it = taintedRegs.find(reg);
  return (it != taintedRegs.end());
}

bool Taint::memIsTainted(uint64_t addr) {
  std::set<uint64_t>::iterator it = taintedMem.find(addr);
  return (it != taintedMem.end());
}

bool Taint::isTainted(uint64_t op, bool isMem) {
  if (isMem) {
    return memIsTainted(op);
  } else {
    return regIsTainted((REG)op);
  }
}

void Taint::markTaint(uint64_t op, bool isMem) {
  if (isMem) {
    markMemTainted(op);
  } else {
    markRegTainted((REG)op);
  }
}

void Taint::clearTaint(uint64_t op, bool isMem) {
  if (isMem) {
    clearMemTainted(op);
  } else {
    clearRegTainted((REG)op);
  }
}

void Taint::markRegTainted(REG reg) {
  taintedRegs.insert(reg);
}

void Taint::clearRegTainted(REG reg) {
  taintedRegs.erase(reg);
}

void Taint::markMemTainted(uint64_t addr) {
  taintedMem.insert(addr);
}

void Taint::clearMemTainted(uint64_t addr) {
  taintedMem.erase(addr);
}

void Taint::printSummary(void) {
  std::cout << std::hex;
  for (std::set<REG>::iterator it = taintedRegs.begin();
       it != taintedRegs.end(); ++it) {
    std::cout << "Reg: " << *it << std::endl;
  }
  std::cout << std::dec;

  std::cout << "Mem set size: " << taintedMem.size() << std::endl;
}

void Taint::reset(void) {
  taintedRegs.clear();
  taintedMem.clear();
}

void Taint::printTaintedSet(std::ostream& stream) {
  for (std::set<REG>::iterator it = taintedRegs.begin();
       it != taintedRegs.end(); ++it) {
    stream << "REG(" << REG_StringShort((REG)*it) << ")" << std::endl;
  }
  for (std::set<uint64_t>::iterator it = taintedMem.begin();
       it != taintedMem.end(); ++it) {
    stream << "MEM(" << std::hex << *it << std::dec << ")" << std::endl;
  }
}

bool Taint::hasTaintedState() {
  return ((taintedRegs.size() > 0) || (taintedMem.size() > 0));
}

bool Taint::hasTaintedFlags() {
  return (taintedRegs.find(REG_RFLAGS) != taintedRegs.end());
}

bool Taint::hasTaintedMemory() { return (taintedMem.size() > 0); }

void Taint::analyzeAndPropagate(tat_instr_t* instr) {
  bool anyReadOperandIsTainted = false;
  bool anyWriteOperandIsTainted = false;
  uint32_t memop_index = 0;

  std::stringstream ss;
  ss << "[";

  // Check if any read operand is tainted
  for (uint32_t i = 0; i < instr->operand_count; i++) {
    tat_operand_access_t access = instr->operand_access[i];
    tat_operand_type_t type = instr->operand_type[i];
    if ((access == TAT_OPERAND_READ) ||
        (access == TAT_OPERAND_READ_AND_WRITTEN)) {
      if (type == TAT_OTYPE_REG) {
        REG reg = instr->operand_register[i];
        ss << "REG(" << REG_StringShort(reg) << ")";
        if (regIsTainted(reg)) {
          anyReadOperandIsTainted = true;
          ss << ".T";
        }
        ss << " ";
      } else if (type == TAT_OTYPE_MEM) {
        uint64_t memea = instr->memops_memea[memop_index];
        uint32_t mem_size = instr->memops_bytes[memop_index];
        REG base_reg = instr->base_register[memop_index];
        REG index_reg = instr->index_register[memop_index];
        ss << "MEM(" << std::hex << memea << std::dec << ", " << mem_size
           << " = " << REG_StringShort(base_reg) << " + "
           << REG_StringShort(index_reg) << ")";
        if (regIsTainted(base_reg) || regIsTainted(index_reg)) {
          anyReadOperandIsTainted = true;
          ss << ".T";
        } else {
          for (uint32_t j = 0; j < mem_size; j++) {
            if (memIsTainted(memea + j)) {
              anyReadOperandIsTainted = true;
              ss << ".T";
              break;
            }
          }
        }
        ss << " ";
      } else if (type == TAT_OTYPE_AGEN) {
        REG index_reg = instr->base_register[0];
        REG base_reg = instr->index_register[0];

        if (index_reg != REG_INVALID()) {
          ss << "REG(" << REG_StringShort(index_reg) << ")";
          if (regIsTainted(index_reg)) {
            anyReadOperandIsTainted = true;
            ss << ".T";
          }
          ss << " ";
        }

        if (base_reg != REG_INVALID()) {
          ss << "REG(" << REG_StringShort(base_reg) << ")";
          if (regIsTainted(base_reg)) {
            anyReadOperandIsTainted = true;
            ss << ".T";
          }
          ss << " ";
        }
      }
    }
    if (type == TAT_OTYPE_MEM) {
      memop_index++;
    }
  }

  ss << "] --> [";
  memop_index = 0;

  // Check if any write operand is tainted
  for (uint32_t i = 0; i < instr->operand_count; i++) {
    tat_operand_access_t access = instr->operand_access[i];
    tat_operand_type_t type = instr->operand_type[i];
    if ((access == TAT_OPERAND_WRITTEN) ||
        (access == TAT_OPERAND_READ_AND_WRITTEN)) {
      if (type == TAT_OTYPE_REG) {
        REG reg = instr->operand_register[i];
        ss << "REG(" << REG_StringShort(reg) << ")";
        if (regIsTainted(reg)) {
          anyWriteOperandIsTainted = true;
          ss << ".T";
        }
        ss << " ";
      } else if (type == TAT_OTYPE_MEM) {
        uint64_t memea = instr->memops_memea[memop_index];
        uint32_t mem_size = instr->memops_bytes[memop_index];
        ss << "MEM(" << std::hex << memea << std::dec << ", " << mem_size
           << ")";
        for (uint32_t j = 0; j < mem_size; j++) {
          if (memIsTainted(memea + j)) {
            anyWriteOperandIsTainted = true;
            ss << ".T";
            break;
          }
        }
        ss << " ";
      }
    }
    if (type == TAT_OTYPE_MEM) {
      memop_index++;
    }
  }

  ss << "]";

  // Apply the taint propagation
  if (anyReadOperandIsTainted) {
    memop_index = 0;
    for (uint32_t i = 0; i < instr->operand_count; i++) {
      tat_operand_access_t access = instr->operand_access[i];
      tat_operand_type_t type = instr->operand_type[i];
      if ((access == TAT_OPERAND_WRITTEN) ||
          (access == TAT_OPERAND_READ_AND_WRITTEN)) {
        if (type == TAT_OTYPE_REG) {
          REG reg = instr->operand_register[i];
          markRegTainted(reg);
        } else if (type == TAT_OTYPE_MEM) {
          uint64_t memea = instr->memops_memea[memop_index];
          uint32_t mem_size = instr->memops_bytes[memop_index];
          for (uint32_t j = 0; j < mem_size; j++) {
            markMemTainted(memea + j);
          }
        }
      }
      if (type == TAT_OTYPE_MEM) {
        memop_index++;
      }
    }
  } else {
    memop_index = 0;
    for (uint32_t i = 0; i < instr->operand_count; i++) {
      tat_operand_access_t access = instr->operand_access[i];
      tat_operand_type_t type = instr->operand_type[i];
      if ((access == TAT_OPERAND_WRITTEN) ||
          (access == TAT_OPERAND_READ_AND_WRITTEN)) {
        if (type == TAT_OTYPE_REG) {
          REG reg = instr->operand_register[i];
          clearRegTainted(reg);
        } else if (type == TAT_OTYPE_MEM) {
          uint64_t memea = instr->memops_memea[memop_index];
          uint32_t mem_size = instr->memops_bytes[memop_index];
          for (uint32_t j = 0; j < mem_size; j++) {
            clearMemTainted(memea + j);
          }
        }
      }
      if (type == TAT_OTYPE_MEM) {
        memop_index++;
      }
    }
  }

  // If anything was tainted, log it
  if ((anyReadOperandIsTainted || anyWriteOperandIsTainted) &&
      tracer->isEnabled()) {
    uint32_t ipVisitCount = ipVisitCounter->getCount(instr->pc);
    tracer->getTaintFile() << std::hex << instr->pc << "." << ipVisitCount
                           << std::dec << ": " << ss.str() << std::endl;
  }
}
