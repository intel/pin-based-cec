/* Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*! @file
 *  Base implementation of the CECTraceTool pintool.
 */

#include <cstdint>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include "MyPinTool.h"
#include "pin.H"
#include "taint.h"
#include "taint_semantics.h"
#include "tracer.h"
#include "visit_counter.h"

#include "tat_instr.h"

/* ================================================================== */
// Global variables
/* ================================================================== */

Tracer* gTracer;
Taint* gTaint;
IpVisitCounter* gIpVisitCounter;
std::unordered_map<std::string, uint64_t>* gImageMap;
bool* gFuncFound;
uint32_t gMallocEntryCount;
uint32_t gReallocEntryCount;

#define ROUND_TO_CACHELINE(x) ((x)&0xFFFFFFFFFFFFFFC0L)
#define ROUND_TO_QWORD(x) ((x)&0xFFFFFFFFFFFFFFF8L)

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobSummaryFile(KNOB_MODE_WRITEONCE, "pintool", "s", "summary.out",
                             "specify file name for CECTraceTool summary");

KNOB<std::string> KnobFuncName(KNOB_MODE_APPEND, "pintool", "f", "func",
                          "specify function name for analysis");

KNOB<std::string> KnobLUTArgIndex(KNOB_MODE_WRITEONCE, "pintool", "l", "0",
                             "argument index of LUT address (experimental)");

KNOB<std::string> KnobAlignList(
    KNOB_MODE_WRITEONCE, "pintool", "A", "",
    "csv list of local allocations to align to cacheline size");

KNOB<std::string> KnobMarkLUT(
    KNOB_MODE_WRITEONCE, "pintool", "m", "no",
    "enable (yes) / disable(no - default) LUT marking in trace log (experimental)");

KNOB<std::string> KnobLUTFuncIndex(KNOB_MODE_WRITEONCE, "pintool", "n", "0",
                              "lut function argument index (experimental)");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage() {
  std::cerr << "This tool generates execution trace and taint analysis info for "
          "finding non-constant time implementation"
       << std::endl;
  std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
  return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

// Called when the program enters any of the target routines.
void EnterTargetRoutine(ADDRINT rsp, ADDRINT argN, uint32_t targetIndex) {
  gTracer->enterTargetRoutine(targetIndex, argN, rsp);
}

// Called when the program exits any of the target routines.
void ExitTargetRoutine(uint32_t targetIndex) {
  gTracer->exitTargetRoutine(targetIndex);
}

void RecordMemRead(ADDRINT ip, ADDRINT memAddr) {
  gTracer->updateMemoryRead(ip, memAddr);
}

void RecordMemWrite(ADDRINT ip, ADDRINT memAddr) {
  gTracer->updateMemoryWrite(ip, memAddr);
}

void RecordInstructionPointer(ADDRINT ip) {
  gTracer->updateInstructionPointer(ip);
  gIpVisitCounter->incrementCount(ip);
}

ADDRINT PIN_FAST_ANALYSIS_CALL InstructionCanBeTainted() {
  return gTaint->hasTaintedState();
}

ADDRINT PIN_FAST_ANALYSIS_CALL FlagsAreTainted() {
  return gTaint->hasTaintedFlags();
}

ADDRINT PIN_FAST_ANALYSIS_CALL MemoryIsTainted() {
  return gTaint->hasTaintedMemory();
}

void PIN_FAST_ANALYSIS_CALL PremarshallMemoryOperand(tat_instr_t* instr,
                                                     uint32_t memop_idx,
                                                     ADDRINT memea) {
  instr->memops_memea[memop_idx] = memea;
}

void PIN_FAST_ANALYSIS_CALL AnalyzeInstructionForTaint(tat_instr_t* instr) {
  gTaint->analyzeAndPropagate(instr);
}

void MarkSecretMemory(ADDRINT addr, ADDRINT size) {
  std::cout << "MarkSecretMemory(" << std::hex << addr << std::dec << ", " << size
       << ")" << std::endl;
  for (ADDRINT i = 0; i < size; i++) {
    gTaint->markTaint(addr + i, true);
  }
}

void ClearSecretMemory(ADDRINT addr, ADDRINT size) {
  std::cout << "ClearSecretMemory(" << std::hex << addr << std::dec << ", " << size
       << ")" << std::endl;
  for (ADDRINT i = 0; i < size; i++) {
    gTaint->clearTaint(addr + i, true);
  }
}

void ClearAllSecretState(void) {
  std::cout << "ClearAllSecretState()" << std::endl;
  gTaint->reset();
}

void InstrumentMemoryAccesses(INS ins, void* v) {
  uint32_t memOperands = INS_MemoryOperandCount(ins);

  // Iterate over each memory operand of the instruction.
  for (uint32_t memOp = 0; memOp < memOperands; memOp++) {
    if (INS_MemoryOperandIsRead(ins, memOp)) {
      INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                               IARG_CALL_ORDER, CALL_ORDER_LAST, IARG_INST_PTR,
                               IARG_MEMORYOP_EA, memOp, IARG_END);
    }
    // Note that in some architectures a single memory operand can be
    // both read and written (for instance incl (%eax) on IA-32)
    // In that case we instrument it once for read and once for write.
    if (INS_MemoryOperandIsWritten(ins, memOp)) {
      INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                               IARG_CALL_ORDER, CALL_ORDER_LAST, IARG_INST_PTR,
                               IARG_MEMORYOP_EA, memOp, IARG_END);
    }
  }

  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordInstructionPointer,
                 IARG_CALL_ORDER, CALL_ORDER_LAST, IARG_INST_PTR, IARG_END);
}

// Wrapper around malloc() that all calls to malloc() will go through.
void* MallocWrapper(AFUNPTR originalFunc, size_t mallocSize, const CONTEXT* ctx, THREADID threadID) {
  VOID* mallocAddress;

  gMallocEntryCount++;
  PIN_CallApplicationFunction(ctx, threadID, CALLINGSTD_DEFAULT, originalFunc, NULL, PIN_PARG(void*), &mallocAddress, PIN_PARG(size_t), mallocSize, PIN_PARG_END());
  gMallocEntryCount--;

  // Only track this allocation if this was a "top-level" malloc() call, i.e. it
  // wasn't called from within malloc() or realloc(). This is necessary because
  // under some conditions, there is at least one level of recursion during
  // malloc() through malloc_hook_ini(). realloc() can also call malloc(), and
  // we want to avoid double-tracking the internal malloc() in that case.
  if ((gMallocEntryCount == 0) && (gReallocEntryCount == 0)) {
    gTracer->addGlobalAllocation((uint64_t)mallocAddress, mallocSize);
  }

  return mallocAddress;
}

// Wrapper around realloc() that all calls to realloc will go through.
void* ReallocWrapper(AFUNPTR originalFunc, void* reallocPtr, size_t reallocSize, const CONTEXT* ctx, THREADID threadID) {
  VOID* reallocAddress;

  gReallocEntryCount++;
  PIN_CallApplicationFunction(ctx, threadID, CALLINGSTD_DEFAULT, originalFunc, NULL, PIN_PARG(void*), &reallocAddress, PIN_PARG(void*), reallocPtr, PIN_PARG(size_t), reallocSize, PIN_PARG_END());
  gReallocEntryCount--;
  
  // Only track this allocation if this was a "top-level" realloc() call, i.e.
  // it wasn't called from within malloc() or realloc(). This is necessary
  // because under some conditions, there is at least one level of recursion
  // that realloc() can go through.
  if ((gMallocEntryCount == 0) && (gReallocEntryCount == 0)) {
    gTracer->removeGlobalAllocation((uint64_t)reallocPtr);
    gTracer->addGlobalAllocation((uint64_t)reallocPtr, reallocSize);
  }

  return reallocAddress;
}

// Wrapper around free() that all calls to free() will go through.
void FreeWrapper(AFUNPTR originalFunc, void* ptrToFree, const CONTEXT* ctx, THREADID threadID) {
  PIN_CallApplicationFunction(ctx, threadID, CALLINGSTD_DEFAULT, originalFunc, NULL, PIN_PARG(void), PIN_PARG(void*), ptrToFree, PIN_PARG_END());
  gTracer->removeGlobalAllocation((uint64_t)ptrToFree);
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

void Image(IMG img, void* v) {
  RTN rtn;
  std::string imgName = IMG_Name(img);

  gImageMap->insert(std::make_pair(imgName, (uint64_t)IMG_LoadOffset(img)));

  // Add all sections in the image to the allocation map.
  for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
    ADDRINT addr = SEC_Address(sec);
    if (addr != 0) {
      std::string name = imgName + SEC_Name(sec);
      gTracer->addSection(addr, SEC_Size(sec), name);
    }
  }

  ADDRINT lutArgIndex = (ADDRINT)atoi(KnobLUTArgIndex.Value().c_str());

  // Instrument all target routines.
  for (unsigned int i = 0; i < KnobFuncName.NumberOfValues(); i++) {
    std::string funcName = KnobFuncName.Value(i);

    rtn = RTN_FindByName(img, funcName.c_str());
    if (RTN_Valid(rtn)) {
      RTN_Open(rtn);
      gFuncFound[i] = true;

      std::cout << "Instrumenting " << funcName << " in " << imgName << "("
                << IMG_Id(img) << ") @ " << std::hex << RTN_Address(rtn)
                << std::dec << std::endl;

      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)EnterTargetRoutine,
                     IARG_REG_VALUE, REG_RSP, IARG_FUNCARG_ENTRYPOINT_VALUE,
                     lutArgIndex,
                     IARG_UINT32, i, IARG_END);

      RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)ExitTargetRoutine, IARG_UINT32,
                     i, IARG_END);

      RTN_Close(rtn);
    }
  }

  // Replace the malloc() function with a wrapper that just calls malloc(),
  // tracks the allocation, and returns the result. We do this instead of just
  // instrumenting malloc() because some malloc() implementations return through
  // an eliminated tail call, which causes PIN to miss the function exit and
  // therefore the exit callback never gets fired and the allocation never gets
  // tracked. If we instead patch and wrap the call to malloc(), we know that we
  // aren't missing any function exits.
  rtn = RTN_FindByName(img, "malloc");
  if (RTN_Valid(rtn)) {
    std::cout << "Replacing malloc() with wrapper in " << imgName << "("
    << IMG_Id(img) << ")" << std::endl;

    PROTO protoMalloc = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT,
                                       "malloc", PIN_PARG(size_t), PIN_PARG_END());
    RTN_ReplaceSignature(rtn, AFUNPTR(MallocWrapper),
                         IARG_PROTOTYPE, protoMalloc,
                         IARG_ORIG_FUNCPTR,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                         IARG_CONST_CONTEXT,
                         IARG_THREAD_ID,
                         IARG_END);
    PROTO_Free(protoMalloc);
  }

  // Replace the realloc() function with a wrapped version that calls realloc(),
  // tracks the allocation, and returns the result.
  rtn = RTN_FindByName(img, "realloc");
  if (RTN_Valid(rtn)) {
    std::cout << "Replacing realloc() with wrapper in " << imgName << "("
    << IMG_Id(img) << ")" << std::endl;

    PROTO protoRealloc = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT,
                                       "realloc", PIN_PARG(void*), PIN_PARG(size_t), PIN_PARG_END());
    RTN_ReplaceSignature(rtn, AFUNPTR(ReallocWrapper),
                         IARG_PROTOTYPE, protoRealloc,
                         IARG_ORIG_FUNCPTR,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                         IARG_CONST_CONTEXT,
                         IARG_THREAD_ID,
                         IARG_END);
    PROTO_Free(protoRealloc);
  }

  // Replace the free() function with a wrapped version that calls free() and
  // stops tracking the allocation.
  rtn = RTN_FindByName(img, "free");
  if (RTN_Valid(rtn)) {
    std::cout << "Replacing free() with wrapper in " << imgName << "("
    << IMG_Id(img) << ")" << std::endl;

    PROTO protoFree = PROTO_Allocate(PIN_PARG(void), CALLINGSTD_DEFAULT,
                                       "free", PIN_PARG(void*), PIN_PARG_END());
    RTN_ReplaceSignature(rtn, AFUNPTR(FreeWrapper),
                         IARG_PROTOTYPE, protoFree,
                         IARG_ORIG_FUNCPTR,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                         IARG_CONST_CONTEXT,
                         IARG_THREAD_ID,
                         IARG_END);
    PROTO_Free(protoFree);
  }

  rtn = RTN_FindByName(img, "PinBasedCEC_MarkSecret");
  if (RTN_Valid(rtn)) {
    std::cout << "Instrumenting PinBasedCEC_MarkSecret() in " << imgName << "("
              << IMG_Id(img) << ")" << std::endl;

    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MarkSecretMemory,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
    RTN_Close(rtn);
  }

  rtn = RTN_FindByName(img, "PinBasedCEC_ClearSecret");
  if (RTN_Valid(rtn)) {
    std::cout << "Instrumenting PinBasedCEC_ClearSecret() in " << imgName << "("
              << IMG_Id(img) << ")" << std::endl;

    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ClearSecretMemory,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
    RTN_Close(rtn);
  }

  rtn = RTN_FindByName(img, "PinBasedCEC_ClearSecrets");
  if (RTN_Valid(rtn)) {
    std::cout << "Instrumenting PinBasedCEC_ClearSecrets() in " << imgName << "("
              << IMG_Id(img) << ")" << std::endl;

    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ClearAllSecretState,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
    RTN_Close(rtn);
  }
}

void saveImageMap(const std::string& filename) {
  std::ofstream outFile(filename.c_str(), std::ios::out);

  outFile << "{" << std::endl;

  for (std::unordered_map<std::string, uint64_t>::iterator it =
           gImageMap->begin();
       it != gImageMap->end(); ++it) {
    if (it != gImageMap->begin()) {
      outFile << "," << std::endl;
    }
    outFile << "\t\"" << it->first << "\": \"" << std::hex << it->second
            << std::dec << "\"";
  }

  outFile << std::endl;
  outFile << "}" << std::endl;

  outFile.close();
}

// Cleanup file handles and determine overall pass/fail
void Fini(INT32 code, void* v) {
  std::string summaryFileName = KnobSummaryFile.Value();
  gTracer->summarize(summaryFileName);

  saveImageMap("image_map");

  delete gTaint;
  delete gTracer;
  delete gIpVisitCounter;
  delete gImageMap;

  std::cout << "Done." << std::endl;
}

// Parse comma-seperated list of labels to treat as 64-bit aligned.
void parseAlignmentKnob() {
  std::string s = KnobAlignList.Value();
  size_t i = 0;
  while (i != std::string::npos) {
    size_t j = s.find(",", i);
    size_t count = (j == std::string::npos) ? std::string::npos : j - i;
    std::string ss = s.substr(i, count);
    if (ss.size() > 0) {
      gTracer->markLocalAllocationAsAligned(ss);
    }
    i = (j == std::string::npos) ? j : j + 1;
  }
}

void makeLogDirectories(void) {
  OS_RETURN_CODE retval;
  OS_FILE_ATTRIBUTES attr;

  retval = OS_GetFileAttributes("memtrace/", &attr);
  if ((retval.generic_err != OS_RETURN_CODE_NO_ERROR) ||
      ((attr & OS_FILE_ATTRIBUTES_EXIST) == 0)) {
    OS_MkDir("memtrace/", OS_FILE_PERMISSION_TYPE_READ |
                              OS_FILE_PERMISSION_TYPE_WRITE |
                              OS_FILE_PERMISSION_TYPE_EXECUTE);
  }

  retval = OS_GetFileAttributes("iptrace/", &attr);
  if ((retval.generic_err != OS_RETURN_CODE_NO_ERROR) ||
      ((attr & OS_FILE_ATTRIBUTES_EXIST) == 0)) {
    OS_MkDir("iptrace/", OS_FILE_PERMISSION_TYPE_READ |
                             OS_FILE_PERMISSION_TYPE_WRITE |
                             OS_FILE_PERMISSION_TYPE_EXECUTE);
  }

  retval = OS_GetFileAttributes("taint/", &attr);
  if ((retval.generic_err != OS_RETURN_CODE_NO_ERROR) ||
      ((attr & OS_FILE_ATTRIBUTES_EXIST) == 0)) {
    OS_MkDir("taint/", OS_FILE_PERMISSION_TYPE_READ |
                           OS_FILE_PERMISSION_TYPE_WRITE |
                           OS_FILE_PERMISSION_TYPE_EXECUTE);
  }
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet
 * started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments,
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char* argv[]) {
  // Initialize PIN library. Print help message if -h(elp) is specified
  // in the command line or the command line is invalid
  // Initialize pin & symbol manager
  PIN_InitSymbols();
  if (PIN_Init(argc, argv)) {
    return Usage();
  }

  makeLogDirectories();

  uint32_t numTargetRoutines = KnobFuncName.NumberOfValues();
  bool markLut = (KnobMarkLUT.Value() == "yes");
  uint32_t lutTargetRoutineIndex = atoi(KnobLUTFuncIndex.Value().c_str());
  uint32_t lutSize = 0;

  gIpVisitCounter = new IpVisitCounter();

  gTracer =
      new Tracer("memtrace", "iptrace", "taint", numTargetRoutines, markLut,
                 lutTargetRoutineIndex, lutSize, gIpVisitCounter);

  parseAlignmentKnob();

  gTaint = new Taint(gTracer, gIpVisitCounter, false);

  gFuncFound = new bool[numTargetRoutines];
  for (uint32_t i = 0; i < numTargetRoutines; i++) {
    gFuncFound[i] = false;
  }

  gImageMap = new std::unordered_map<std::string, uint64_t>();

  gMallocEntryCount = 0;
  gReallocEntryCount = 0;

  // Register Image to be called to instrument functions.
  IMG_AddInstrumentFunction(Image, 0);
  INS_AddInstrumentFunction(TaintInstruction, 0);
  INS_AddInstrumentFunction(InstrumentMemoryAccesses, 0);
  PIN_AddFiniFunction(Fini, 0);

  // Start the program, never returns
  PIN_StartProgram();

  return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
