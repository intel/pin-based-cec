/* Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "../vendor/CRCpp/inc/CRC.h"
#include "tracer.h"

Tracer::Tracer(std::string _traceMemFilePath, std::string _traceIPFilePath,
               std::string _taintFilePath, uint32_t numTargetRoutines,
               bool _markLut, uint32_t _lutTargetRoutineIndex,
               uint32_t _lutSize, IpVisitCounter *_ipVisitCounter) {
  nextLocalLabelId = 0;
  nextGlobalLabelId = 0;
  savedRSP = 0;
  exitCount = 0;
  enabled = false;
  instructionPointerDigest = 0xFFFFFFFF;
  memoryAccessDigest = 0xFFFFFFFF;
  currentTargetRoutineMask = 0;
  refTargetRoutineMask = (1 << numTargetRoutines) - 1;
  traceMemFilePath = _traceMemFilePath;
  traceIPFilePath = _traceIPFilePath;
  taintFilePath = _taintFilePath;
  markLut = _markLut;
  lutAddress = 0;
  lutSize = _lutSize;
  lutTargetRoutineIndex = _lutTargetRoutineIndex;
  taintFlag = false;
  onlyConsumeTaintedInstructions = false;
  ipVisitCounter = _ipVisitCounter;
}

Tracer::~Tracer() {
  traceMemFile.close();
  traceIPFile.close();
  taintFile.close();

  for (std::map<uint64_t, AllocationRecord *>::iterator it =
           allocationMap.begin();
       it != allocationMap.end(); ++it) {
    free(it->second);
  }

  for (std::map<uint64_t, AllocationRecord *>::iterator it = sectionMap.begin();
       it != sectionMap.end(); ++it) {
    free(it->second);
  }
}

void Tracer::updateInstructionPointer(uint64_t ip) {
  if (enabled) {
    uint32_t ipVisitCount = ipVisitCounter->getCount(ip);

    traceIPFile << "IP: " << ip << "." << ipVisitCount << std::endl;

    updateInstructionPointerDigest(ip);
  }

  taintFlag = false;
}

void Tracer::updateMemoryRead(uint64_t ip, uint64_t addr) {
  if (enabled) {
    uint32_t ipVisitCount = ipVisitCounter->getCount(ip);

    TaggedMemoryAddress taggedAddress;
    convertMemoryAddressToTag(addr, &taggedAddress);

    traceMemFile << "MemRead: " << ip << "." << ipVisitCount << " (";

    if (taggedAddress.type == MEM_TAG_POS_RSP_OFFSET) {
      traceMemFile << "rsp + " << taggedAddress.value;
    } else if (taggedAddress.type == MEM_TAG_NEG_RSP_OFFSET) {
      traceMemFile << "rsp - " << taggedAddress.value;
    } else if (taggedAddress.type == MEM_TAG_ALLOC) {
      if (isLocalAllocationAligned(taggedAddress.localLabel)) {
        ADDRINT alignedAllocationAddr = ALIGN64(taggedAddress.start);
        ADDRINT alignedDelta = addr - alignedAllocationAddr;
        traceMemFile << "ALIGN64(" << taggedAddress.localLabel << " + "
		     << alignedDelta << ")";
      } else {
        traceMemFile << taggedAddress.localLabel <<  " + "
		     << taggedAddress.value;
      }
    } else if (taggedAddress.type == MEM_TAG_SECTION) {
      traceMemFile << taggedAddress.label << " + " << taggedAddress.value;
    } else if (taggedAddress.type == MEM_TAG_ABSOLUTE) {
      traceMemFile << taggedAddress.value;
    }

    traceMemFile << ")" << std::endl;

    updateMemoryAccessDigest(ip, &taggedAddress, false, false);
  }
}

void Tracer::updateMemoryWrite(uint64_t ip, uint64_t addr) {
  if (enabled) {
    uint32_t ipVisitCount = ipVisitCounter->getCount(ip);

    TaggedMemoryAddress taggedAddress;
    convertMemoryAddressToTag(addr, &taggedAddress);

    traceMemFile << "MemWrite: " << ip << "." << ipVisitCount << " (";

    if (taggedAddress.type == MEM_TAG_POS_RSP_OFFSET) {
      traceMemFile << "rsp + " << taggedAddress.value;
    } else if (taggedAddress.type == MEM_TAG_NEG_RSP_OFFSET) {
      traceMemFile << "rsp - " << taggedAddress.value;
    } else if (taggedAddress.type == MEM_TAG_ALLOC) {
      if (isLocalAllocationAligned(taggedAddress.localLabel)) {
        ADDRINT alignedAllocationAddr = ALIGN64(taggedAddress.start);
        ADDRINT alignedDelta = addr - alignedAllocationAddr;
        traceMemFile << "ALIGN64(" << taggedAddress.localLabel << " + "
		     << alignedDelta << ")";
      } else {
        traceMemFile << taggedAddress.localLabel << " + "
		     << taggedAddress.value;
      }
    } else if (taggedAddress.type == MEM_TAG_SECTION) {
      traceMemFile << taggedAddress.label << " + " << taggedAddress.value;
    } else if (taggedAddress.type == MEM_TAG_ABSOLUTE) {
      traceMemFile << taggedAddress.value;
    }

    traceMemFile << ")" << std::endl;

    updateMemoryAccessDigest(ip, &taggedAddress, true, false);
  }
}

void Tracer::enterTargetRoutine(uint32_t targetRoutineIndex, uint64_t argNValue,
                                uint64_t rsp) {
  uint32_t newTargetRoutineMask =
      currentTargetRoutineMask | (1 << targetRoutineIndex);

  if ((newTargetRoutineMask == refTargetRoutineMask) &&
      (currentTargetRoutineMask != refTargetRoutineMask)) {
    enabled = true;
    savedRSP = rsp;
    nextLocalLabelId = 0;
    instructionPointerDigest = 0xFFFFFFFF;
    memoryAccessDigest = 0xFFFFFFFF;
    openTraceMemFile();
    openTraceIPFile();
    openTaintFile();
    traceMemFile << "TraceMemStart" << std::endl;
    traceIPFile << "TraceIPStart" << std::endl;
    taintFile << "TraceStart" << std::endl;
    ipVisitCounter->reset();
    ipVisitCounter->enable();
  }

  if (markLut && (targetRoutineIndex == lutTargetRoutineIndex)) {
    lutAddress = argNValue;
  }

  currentTargetRoutineMask = newTargetRoutineMask;
}

void Tracer::exitTargetRoutine(uint32_t targetRoutineIndex) {
  uint32_t newTargetRoutineMask =
      currentTargetRoutineMask & ~(1 << targetRoutineIndex);
  if ((newTargetRoutineMask != refTargetRoutineMask) &&
      (currentTargetRoutineMask == refTargetRoutineMask)) {
    enabled = false;
    exitCount++;
    instructionPointerDigestHistory.push_back(instructionPointerDigest);
    memoryAccessDigestHistory.push_back(memoryAccessDigest);
    traceMemFile << "TraceMemEnd" << std::endl;
    traceIPFile << "TraceIPEnd" << std::endl;
    taintFile << "TraceEnd" << std::endl;

    finalizeTraceMemFile();
    finalizeTraceIPFile();
    finalizeTaintFile();

    ipVisitCounter->disable();
    ipVisitCounter->reset();
  }
  currentTargetRoutineMask = newTargetRoutineMask;
}

AllocationRecord *Tracer::findAllocation(uint64_t addr) {
  std::map<uint64_t, AllocationRecord *>::iterator it =
      allocationMap.upper_bound(addr);

  if (it == allocationMap.begin()) {
    return NULL;
  }

  --it;
  if ((addr >= it->second->addr) &&
      (addr < (it->second->addr + it->second->size))) {
    return it->second;
  } else {
    return NULL;
  }
  return NULL;
}

AllocationRecord *Tracer::findSection(uint64_t addr) {
  std::map<uint64_t, AllocationRecord *>::iterator it =
      sectionMap.upper_bound(addr);

  if (it == sectionMap.begin()) {
    return NULL;
  }

  --it;
  if ((addr >= it->second->addr) &&
      (addr < (it->second->addr + it->second->size))) {
    return it->second;
  } else {
    return NULL;
  }
}

void Tracer::convertMemoryAddressToTag(uint64_t addr,
                                       TaggedMemoryAddress *outTag) {
  if ((addr >= savedRSP) && (addr < (savedRSP + 8192))) {
    outTag->type = MEM_TAG_POS_RSP_OFFSET;
    outTag->value = addr - savedRSP;
    return;
  }

  if ((addr < savedRSP) && (addr >= (savedRSP - 8192))) {
    outTag->type = MEM_TAG_NEG_RSP_OFFSET;
    outTag->value = savedRSP - addr;
    return;
  }

  AllocationRecord *alloc = findAllocation(addr);
  if (alloc != NULL) {
    outTag->type = MEM_TAG_ALLOC;
    outTag->label = alloc->label;
    outTag->localLabel = localizeAllocationLabel(alloc->label);
    outTag->value = addr - alloc->addr;
    outTag->start = alloc->addr;
    return;
  }

  AllocationRecord *sec = findSection(addr);
  if (sec != NULL) {
    outTag->type = MEM_TAG_SECTION;
    outTag->label = sec->label;
    outTag->value = addr - sec->addr;
    outTag->start = sec->addr;
    return;
  }

  outTag->type = MEM_TAG_ABSOLUTE;
  outTag->value = addr;
}

std::string Tracer::localizeAllocationLabel(std::string &globalLabel) {
  std::map<std::string, std::string>::iterator it =
      globalToLocalAllocationLabelMap.find(globalLabel);
  if (it == globalToLocalAllocationLabelMap.end()) {
    std::stringstream ss;
    ss << "lmem" << nextLocalLabelId;
    nextLocalLabelId += 1;
    std::string localLabel = ss.str();
    globalToLocalAllocationLabelMap.insert(
        std::pair<std::string, std::string>(globalLabel, localLabel));
    return localLabel;
  } else {
    return it->second;
  }
}

void Tracer::addGlobalAllocation(uint64_t addr, uint64_t size) {
  std::stringstream ss;
  ss << "mem" << nextGlobalLabelId;
  nextGlobalLabelId += 1;
  std::string label = ss.str();

  std::map<uint64_t, AllocationRecord *>::iterator it =
      allocationMap.find(addr);
  if (it == allocationMap.end()) {
    AllocationRecord *alloc =
        (AllocationRecord *)malloc(sizeof(AllocationRecord));
    alloc->addr = addr;
    alloc->size = size;
    alloc->label = label;
    allocationMap[addr] = alloc;
  } else {
    free(it->second);
    AllocationRecord *alloc =
        (AllocationRecord *)malloc(sizeof(AllocationRecord));
    alloc->addr = addr;
    alloc->size = size;
    alloc->label = label;
    allocationMap[addr] = alloc;
  }
}

void Tracer::removeGlobalAllocation(uint64_t addr) {
  std::map<uint64_t, AllocationRecord *>::iterator it =
      allocationMap.find(addr);
  if (it != allocationMap.end()) {
    free(it->second);
    allocationMap.erase(addr);
  }
}

void Tracer::addSection(uint64_t addr, uint64_t size, const std::string &name) {
  std::map<uint64_t, AllocationRecord *>::iterator it = sectionMap.find(addr);
  if (it == allocationMap.end()) {
    AllocationRecord *alloc =
        (AllocationRecord *)malloc(sizeof(AllocationRecord));
    alloc->addr = addr;
    alloc->size = size;
    alloc->label = name;
    sectionMap[addr] = alloc;
  } else {
    free(it->second);
    AllocationRecord *alloc =
        (AllocationRecord *)malloc(sizeof(AllocationRecord));
    alloc->addr = addr;
    alloc->size = size;
    alloc->label = name;
    sectionMap[addr] = alloc;
  }
}

void Tracer::updateInstructionPointerDigest(uint64_t ip) {
  instructionPointerDigest = CRC::Calculate(
      (char *)&ip, sizeof(uint64_t), CRC::CRC_32(), instructionPointerDigest);
}

void Tracer::updateMemoryAccessDigest(uint64_t ip,
                                      TaggedMemoryAddress *taggedAddress,
                                      bool isWrite, bool isAligned) {
  uint8_t readWrite = isWrite ? 1 : 0;
  uint8_t aligned = isAligned ? 1 : 0;
  memoryAccessDigest = CRC::Calculate((char *)&ip, sizeof(uint64_t),
                                      CRC::CRC_32(), memoryAccessDigest);
  memoryAccessDigest = CRC::Calculate((char *)&readWrite, sizeof(uint8_t),
                                      CRC::CRC_32(), memoryAccessDigest);
  memoryAccessDigest =
      CRC::Calculate((char *)&taggedAddress->type, sizeof(uint32_t),
                     CRC::CRC_32(), memoryAccessDigest);
  memoryAccessDigest =
      CRC::Calculate((char *)&taggedAddress->value, sizeof(uint64_t),
                     CRC::CRC_32(), memoryAccessDigest);
  if (taggedAddress->type == MEM_TAG_ALLOC) {
    // Here we want to add the localized label of the allocation rather than the
    // global label to ensure that digests remain relative to each Function
    // Under Test invocation, so they can be compared with each other.
    memoryAccessDigest = CRC::Calculate((char *)taggedAddress->localLabel.c_str(),
                                        taggedAddress->localLabel.size(),
                                        CRC::CRC_32(), memoryAccessDigest);
    memoryAccessDigest = CRC::Calculate((char *)&aligned, sizeof(uint8_t),
                                        CRC::CRC_32(), memoryAccessDigest);
  }
}

uint32_t Tracer::summarize(const std::string &summaryFileName) {
  uint32_t verdict;
  std::ofstream summaryFile(summaryFileName.c_str());
  summaryFile << "Iterations detected: " << exitCount << std::endl;

  if (exitCount >= 2) {
    bool pass = true;
    uint32_t i;

    std::vector<uint32_t>::iterator ipIt =
        instructionPointerDigestHistory.begin();
    uint32_t ipDigestRef = *ipIt;
    ++ipIt;
    for (i = 2; ipIt != instructionPointerDigestHistory.end(); ++ipIt, ++i) {
      uint32_t ipDigest = *ipIt;
      if (ipDigest != ipDigestRef) {
        pass = false;
        summaryFile << "Instruction pointer digest mismatch: (1: "
                    << ipDigestRef << ") vs (" << i << ": " << ipDigest << ")"
                    << std::endl;
      }
    }

    std::vector<uint32_t>::iterator memIt = memoryAccessDigestHistory.begin();
    uint32_t memDigestRef = *memIt;
    ++memIt;
    for (i = 2; memIt != memoryAccessDigestHistory.end(); ++memIt, ++i) {
      uint32_t memDigest = *memIt;
      if (memDigest != memDigestRef) {
        pass = false;
        summaryFile << "Memory access digest mismatch: (1: " << memDigestRef
                    << ") vs (" << i << ": " << memDigest << ")" << std::endl;
      }
    }

    if (pass) {
      summaryFile << "PASS" << std::endl;
      verdict = VERDICT_PASS;
    } else {
      summaryFile << "FAIL" << std::endl;
      verdict = VERDICT_FAIL;
    }
  } else {
    summaryFile << "INCONCLUSIVE" << std::endl;
    verdict = VERDICT_INCONCLUSIVE;
  }

  summaryFile.close();
  return verdict;
}

void Tracer::markLocalAllocationAsAligned(std::string &localLabel) {
  alignedLocalAllocations.insert(localLabel);
}

bool Tracer::isLocalAllocationAligned(std::string &localLabel) {
  std::set<std::string>::iterator it = alignedLocalAllocations.find(localLabel);
  return (it != alignedLocalAllocations.end());
}

bool Tracer::isLutAddr(uint64_t addr) {
  return ((addr >= ALIGN64(lutAddress)) &&
          (addr < (ALIGN64(lutAddress) + lutSize)));
}

void Tracer::setTaintFlag(void) { taintFlag = true; }

void Tracer::clearTaintFlag(void) { taintFlag = false; }

void Tracer::openTraceMemFile(void) {
  if (traceMemFile.is_open()) {
    traceMemFile.close();
  }

  std::stringstream traceStream;
  traceStream << traceMemFilePath << "/trace" << exitCount;
  traceMemFileName = traceStream.str();
  std::cout << "Opening trace mem file: " << traceMemFileName << std::endl;
  traceMemFile.open(traceMemFileName.c_str());
  traceMemFile << std::hex;
}

void Tracer::openTraceIPFile(void) {
  if (traceIPFile.is_open()) {
    traceIPFile.close();
  }

  std::stringstream traceStream;
  traceStream << traceIPFilePath << "/trace" << exitCount;
  traceIPFileName = traceStream.str();
  std::cout << "Opening trace IP file: " << traceIPFileName << std::endl;
  traceIPFile.open(traceIPFileName.c_str());
  traceIPFile << std::hex;
}

void Tracer::openTaintFile(void) {
  if (taintFile.is_open()) {
    taintFile.close();
  }

  std::stringstream taintStream;
  taintStream << taintFilePath << "/taint" << exitCount;
  taintFileName = taintStream.str();
  taintFile.open(taintFileName.c_str());
  taintFile << std::hex;
}

void Tracer::finalizeTraceMemFile(void) {
  traceMemFile.close();

  if (exitCount < 2) {
    return;
  }

  uint32_t refMemDigest = memoryAccessDigestHistory.at(0);
  uint32_t lastMemDigest = memoryAccessDigestHistory.at(exitCount - 1);

  if (refMemDigest == lastMemDigest) {
    std::remove(traceMemFileName.c_str());
  }
}

void Tracer::finalizeTraceIPFile(void) {
  traceIPFile.close();

  if (exitCount < 2) {
    return;
  }

  uint32_t refIpDigest = instructionPointerDigestHistory.at(0);
  uint32_t lastIpDigest = instructionPointerDigestHistory.at(exitCount - 1);

  if (refIpDigest == lastIpDigest) {
    std::remove(traceIPFileName.c_str());
  }
}

void Tracer::finalizeTaintFile(void) {
  taintFile.close();

  if (exitCount < 2) {
    return;
  }

  uint32_t refIpDigest = instructionPointerDigestHistory.at(0);
  uint32_t lastIpDigest = instructionPointerDigestHistory.at(exitCount - 1);

  uint32_t refMemDigest = memoryAccessDigestHistory.at(0);
  uint32_t lastMemDigest = memoryAccessDigestHistory.at(exitCount - 1);

  if ((refIpDigest == lastIpDigest) && (refMemDigest == lastMemDigest)) {
    std::remove(taintFileName.c_str());
  }
}

bool Tracer::isEnabled(void) { return enabled; }

std::ofstream &Tracer::getTaintFile(void) { return taintFile; }
