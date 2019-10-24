/* Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __TAINT_H__
#define __TAINT_H__

#include <stdint.h>
#include <fstream>
#include <set>
#include <vector>
#include "pin.H"
#include "tracer.h"
#include "visit_counter.h"

#include "tat_instr.h"

class Taint {
 public:
  Taint(Tracer* _tracer, IpVisitCounter* _ipVisitCounter, bool _ignoreRIP);
  ~Taint();
  void printSummary(void);
  void markTaint(uint64_t, bool);
  void clearTaint(uint64_t, bool);
  void reset(void);
  void printTaintedSet(std::ostream& stream);
  bool hasTaintedState();
  bool hasTaintedMemory();
  bool hasTaintedFlags();
  void analyzeAndPropagate(tat_instr_t*);

 private:
  bool isTainted(uint64_t, bool);
  void markRegTainted(REG reg);
  void clearRegTainted(REG reg);
  void markMemTainted(uint64_t);
  void clearMemTainted(uint64_t);
  bool regIsTainted(REG reg);
  bool memIsTainted(uint64_t);
  std::set<REG> taintedRegs;
  std::set<uint64_t> taintedMem;
  Tracer* tracer;
  IpVisitCounter* ipVisitCounter;
  bool ignoreRIP;
};

#endif
