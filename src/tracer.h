/* Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __TRACER_H__
#define __TRACER_H__

#include <stdint.h>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>
#include "visit_counter.h"

#define MEM_TAG_POS_RSP_OFFSET 0
#define MEM_TAG_NEG_RSP_OFFSET 1
#define MEM_TAG_ALLOC 2
#define MEM_TAG_SECTION 3
#define MEM_TAG_ABSOLUTE 4

#define ALIGN64(x) (((x + 63) >> 6) << 6)

#define VERDICT_PASS 1
#define VERDICT_FAIL 2
#define VERDICT_INCONCLUSIVE 3

struct TaggedMemoryAddress {
  uint32_t type;
  std::string label;
  std::string localLabel;
  uint64_t value;
  uint64_t start;
};

struct AllocationRecord {
  uint64_t addr;
  uint64_t size;
  std::string label;
};

class Tracer {
 public:
  Tracer(std::string, std::string, std::string, uint32_t, bool, uint32_t,
         uint32_t, IpVisitCounter*);
  ~Tracer();
  void updateInstructionPointer(uint64_t);
  void updateMemoryRead(uint64_t, uint64_t);
  void updateMemoryWrite(uint64_t, uint64_t);
  void enterTargetRoutine(uint32_t, uint64_t, uint64_t);
  void exitTargetRoutine(uint32_t);
  void addGlobalAllocation(uint64_t, uint64_t);
  void removeGlobalAllocation(uint64_t);
  void addSection(uint64_t, uint64_t, const std::string&);
  void markLocalAllocationAsAligned(std::string&);
  uint32_t summarize(const std::string&);
  void setTaintFlag(void);
  void clearTaintFlag(void);
  bool isEnabled(void);
  std::ofstream& getTaintFile(void);

 private:
  bool enabled;
  bool taintFlag;
  bool onlyConsumeTaintedInstructions;
  uint32_t instructionPointerDigest;
  uint32_t memoryAccessDigest;
  std::ofstream traceMemFile;
  std::ofstream traceIPFile;
  std::ofstream taintFile;
  std::string traceMemFilePath;
  std::string traceIPFilePath;
  std::string taintFilePath;
  std::string traceMemFileName;
  std::string traceIPFileName;
  std::string taintFileName;
  uint32_t currentTargetRoutineMask;
  uint32_t refTargetRoutineMask;
  uint32_t nextLocalLabelId;
  uint32_t nextGlobalLabelId;
  uint64_t savedRSP;
  uint32_t exitCount;
  bool markLut;
  uint64_t lutAddress;
  uint32_t lutSize;
  uint32_t lutTargetRoutineIndex;
  std::map<uint64_t, AllocationRecord*> allocationMap;
  std::map<uint64_t, AllocationRecord*> sectionMap;
  std::map<std::string, std::string> globalToLocalAllocationLabelMap;
  std::vector<uint32_t> instructionPointerDigestHistory;
  std::vector<uint32_t> memoryAccessDigestHistory;
  std::set<std::string> alignedLocalAllocations;
  IpVisitCounter* ipVisitCounter;
  void updateInstructionPointerDigest(uint64_t);
  void updateMemoryAccessDigest(uint64_t, TaggedMemoryAddress*, bool, bool);
  void convertMemoryAddressToTag(uint64_t, TaggedMemoryAddress*);
  std::string localizeAllocationLabel(std::string&);
  AllocationRecord* findAllocation(uint64_t);
  AllocationRecord* findSection(uint64_t);
  bool isLutAddr(uint64_t);
  bool isLocalAllocationAligned(std::string&);
  void openTraceMemFile(void);
  void openTraceIPFile(void);
  void openTaintFile(void);
  void finalizeTraceMemFile(void);
  void finalizeTraceIPFile(void);
  void finalizeTaintFile(void);
};

#endif
