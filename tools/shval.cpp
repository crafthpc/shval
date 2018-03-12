/*
 * Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * Written by Michael O. Lam, lam26@llnl.gov. LLNL-CODE-729118.
 * All rights reserved.
 *
 * This file is part of SHVAL. For details, see https://github.com/lam2mo/shval
 *
 * Please also see the LICENSE file for our notice and the LGPL.
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License (as published by the Free
 * Software Foundation) version 2.1 dated February 1999.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the IMPLIED WARRANTY OF MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the terms and conditions of the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 * This Pintool tracks floating-point values throughout execution of an x86
 * program. For every floating-point value that is encountered, the tool creates
 * a corresponding shadow value and stores it in an internal data structure. For
 * every instruction that operates on a floating-point value, the tool performs
 * the corresponding operation on the associated shadow value(s). This simulates
 * running the original program with a different real number representation.
 *
 * Example:
 *
 *  ORIGINAL CODE:                          SHADOW VALUE CODE:
 *
 *      double x = 1.2;                         SH_ALLOC(xs)
 *                                              SH_SET(xs, 1.2)
 *
 *      double y = 3.4;                         SH_ALLOC(ys)
 *                                              SH_SET(ys, 3.4)
 *
 *      x = x + y;                              SH_ADD(xs, ys)
 *
 *      y = sqrt(x);                            SH_SQRT(ys, xs)
 *
 * Of course, the actual shadow value code is inserted at the binary instruction
 * level rather than the source code level, but the above example should serve
 * to demonstrate the concept.
 *
 * At the end of execution, the tool examines the final shadow values and
 * compares them with the actual values at the corresponding memory locations,
 * reporting an error if the value has a high relative error (or is otherwise
 * divergent by whatever definition is appropriate for a given shadow value
 * type).
 *
 * The analysis currently performs shadow value analysis for all 64-bit
 * floating- point values encountered in memory during execution as well as
 * 128-bit SSE registers (XMM0-XMM15). There is some preliminary work in support
 * of shadow values analysis of 32-bit floating-point values, but this support
 * is NOT complete yet. If you wish to analyze a program, it should be compiled
 * to use ONLY 64-bit floating-point values (i.e., the "double" data type in
 * C/C++). In addition, AVX support is not yet complete; analysis of programs
 * that use AVX instructions or 256-bit registers is likely to be incorrect.
 *
 * This file does not define a complete tool; it requires SH_* macros that are
 * undefined here. The intended use is to create shval-X.cpp files that have the
 * macros defined for whatever type of shadow value you want, and have that file
 * #include this one. It's a bit hacky, but it gives us the best compiler
 * optimizations while retaining a manageable code base.
 *
 * Here are the required macros. The first macro is merely textual and must
 * expand to a type definition usable for declaring shadow values.
 *
 *  SH_TYPE         shadow value type (used for shadow value tables)
 *  SH_PACKED_TYPE  packed shadow value type (used for MPI communication)
 *
 * The following required macros are statements (i.e., their expansions are not
 * meant to be used in a larger expression). All macros should be defined; any
 * macro that is not needed for a particular shadow value type should be defined
 * to be ";".
 *
 *  SH_INIT         initialization
 *  SH_FINI         cleanup
 *
 *  SH_ALLOC(V)     allocate shadow value V (necessary if SH_TYPE is a ptr type)
 *  SH_FREE(V)      de-allocate shadow value V
 *
 *  SH_SET(V,X)     set shadow value V to X (double)
 *  SH_COPY(V,S)    set shadow value V equal to S (another shadow value)
 *  SH_OUTPUT(O,V)  convert V to string and print to ostream O
 *
 *  SH_PACK(P,V)    pack shadow value V into packed value P (for MPI send)
 *  SH_UNPACK(V,P)  unpack value P into shadow value V (for MPI recv)
 *
 *  SH_ADD(V,S)     shadow value addition:       V = V + S
 *  SH_SUB(V,S)     shadow value subtraction:    V = V - S
 *  SH_MUL(V,S)     shadow value multiplication: V = V * S
 *  SH_DIV(V,S)     shadow value division:       V = V / S
 *  SH_MIN(V,S)     shadow value minimum:        V = min(V, S)
 *  SH_MAX(V,S)     shadow value maximum:        V = max(V, S)
 *  SH_SQRT(V,S)    shadow value square root:    V = sqrt(S)
 *  SH_ABS(V,S)     shadow value absolute value: V = |S|
 *  SH_NEG(V,S)     shadow value negation:       V = -S
 *  SH_RND(V,S)     shadow value rounding:       V = int(S)
 *
 * The following required macros are expressions (i.e., their expansions should
 * evaluate to the given types and should be usable in a larger expression).
 *
 *  SH_INFO         string:  human-readable description of shadow value type
 *  SH_PARAMS       string:  human-readable description of parameter(s)
 *
 *  SH_DBL(V)       double:  converted value of shadow value V
 *  SH_RELERR(V,X)  double:  relative error for V given system value X
 *  SH_ISERR(V,X)   boolean: true if this is a reportable error, false otherwise
 *
 * If you are planning to add a new shadow value type, it is recommended that
 * you start by looking at the various existing shadow value analyses,
 * especially native32 and mpfr. You can also use them as boilerplate for
 * your analysis. Remember to edit makefile.rules to add your new analysis file,
 * both at the top in TEST_TOOL_ROOTS and at the bottom if it requires any
 * custom compiler/linker options.
 *
 * Shadow value type implementations are welcome to add more Pin knobs for
 * controlling parameters of the shadow values; however, single-letter
 * parameters are reserved for the core tool framework (i.e., the variables and
 * functions defined in this file).
 */


/******************************************************************************
 *                          HEADERS AND DEFINITIONS
 ******************************************************************************/

/*
 * dependencies: STL containers and standard C libraries
 */
#include <cassert>
#include <csetjmp>
#include <csignal>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <set>
#include <unordered_map>
using namespace std;

/*
 * Linux-specific: used for gethostname() and gettimeofday()
 */
#include <unistd.h>
#include <sys/time.h>
#define MAX_HOSTNAME_LEN 32

/*
 * dependencies: Intel Pin and XED
 */
#include "pin.H"
extern "C" {
#include "xed-interface.h"
}

/*
 * optional: include MPI wrappers
 */
#if USE_MPI
#include <mpi.h>
#define MPI_SHVAL_TAG 999
#endif

/*
 * output filename placeholder
 */
#define DEFAULT_OUT_FN  "{APP}-shval-{HOST}-{PID}.log"

/*
 * runtime asserts are disabled by default if not compiled in DEBUG mode
 */
#if DEBUG
#define DBG_ASSERT(X) assert(X)
#else
#define DBG_ASSERT(X) ;
#endif

/*
 * enable/disable full logging of floating-point value overwriting
 * (extremely expensive, but can help with debugging)
 */
#define ENABLE_OVERWRITE_LOGGING 0

/*
 * command-line options (uses Pin's "knob" interface)
 */
KNOB<string> KnobOutFile(KNOB_MODE_WRITEONCE, "pintool",
        "o", DEFAULT_OUT_FN, "output file name");
KNOB<string> KnobReportFunction(KNOB_MODE_WRITEONCE, "pintool",
        "f", "main", "dump shadow values after the given routine (default=main)");
KNOB<bool>   KnobReportAll(KNOB_MODE_WRITEONCE, "pintool",
        "a", "0", "dump all shadow values in memory, not just errors (default=0)");
KNOB<bool>   KnobStdOutShadowDump(KNOB_MODE_WRITEONCE, "pintool",
        "s", "0", "report shadow values to stdout instead of output file (default=0)");
KNOB<bool>   KnobSkipSummary(KNOB_MODE_WRITEONCE, "pintool",
        "q", "0", "quiet: don't print summary to stdout (default=0)");
KNOB<bool>   KnobOnlineCheck(KNOB_MODE_WRITEONCE, "pintool",
        "c", "0", "check values online (expensive!) (default=0)");
KNOB<bool>   KnobOnlineTraceInsAddrs(KNOB_MODE_WRITEONCE, "pintool",
        "T", "0", "track instruction addresses (very expensive!) (default=0)");
KNOB<bool>   KnobOnlineCheckRegs(KNOB_MODE_WRITEONCE, "pintool",
        "C", "0", "check values online, including registers (VERY expensive!) (default=0)");
KNOB<UINT64> KnobMaximumErrors(KNOB_MODE_WRITEONCE, "pintool",
        "m", "1000", "maximum online errors to report before aborting (default=1000)");

/*
 * application info and output file
 */
static string appName = "default";
static INT    appPid  = 0;
static string hostname = "localhost";
static string outFilename = DEFAULT_OUT_FN;
static ofstream outFile;
static struct timeval startTime;
static struct timeval endTime;

/*
 * disassembled instructions (used for debugging output)
 */
static unordered_map<ADDRINT,string> insDisas;
static unordered_map<ADDRINT,string> insFunc;

/*
 * address tracker -- this allows access to the current instruction address in
 * analysis routines
 */

static ADDRINT currentInsAddr = 0x0;

void setCurrentInsAddr(ADDRINT addr)
{
    currentInsAddr = addr;
}

ADDRINT getCurrentInsAddr()
{
    return currentInsAddr;
}


/******************************************************************************
 *                        SHADOW VALUE DATA STRUCTURES
 ******************************************************************************/

/*
 * shadow values for XMM registers (four shadow slots per register)
 */
static SH_TYPE xmm[16*4];   // striped: all first slots, then all second, etc.

/*
 * quick calculation of XMM slot offsets via register id and tag
 */
#define XMM_SLOT(R,T) ((T)*16+(R))

/*
 * shadow values for memory locations--there are two main implementations: 1) a
 * basic STL unordered map and 2) a hand-written bitmask-based array
 */

#define USE_STL_MAP 1

#if USE_STL_MAP

/*
 * IMPLEMENTATION #1: STL unordered map (slow but simple)
 */

static unordered_map<ADDRINT,SH_TYPE> memMapStd;

#define SHMEM_INIT          ;
#define SHMEM_ACCESS(X)     memMapStd[X]
#define SHMEM_SET_VALID(X)  ;
#define SHMEM_CLEAR(X)      memMapStd.erase(X)
#define SHMEM_IS_VALID(X)   (memMapStd.find(X) != memMapStd.end())
#define SHMEM_SIZE          memMapStd.size()
#define SHMEM_FOR_EACH(X)   for (auto it = memMapStd.begin(); it != memMapStd.end(); it++) { \
                                (X) = it->first;
#define SHMEM_FINI          memMapStd.clear()

#else

/*
 * IMPLEMENTATION #2: hand-written bitmask-based pre-allocated array
 *                    (faster but vulnerable to collisions)
 */

static SH_TYPE *memMapValue;
static bool    *memMapValid;
static ADDRINT *memMapAddr;

//
// SHADOW VALUE TABLE SIZE (choose one of the following)
//

// 28 bits (~4GB base cost for native64; ~10GB for mpfr128)
//#define SHMEM_MAXSIZE  0x10000000
//   (standard)
//#define SHMEM_MASK      0xFFFFFFF
//   (ignore last two bits)
//#define SHMEM_MASK     0x3FFFFFFA

// 30 bits (~17GB base cost for native64; ~41GB for mpfr128)
//#define SHMEM_MAXSIZE  0x40000000
//   (standard)
//#define SHMEM_MASK     0x3FFFFFFF
//   (ignore last two bits)
//#define SHMEM_MASK     0xFFFFFFFA

// 31 bits (~34GB base cost for native64; ~82GB for mpfr128) -- RECOMMENDED
#define SHMEM_MAXSIZE  0x80000000
//   (standard)
//#define SHMEM_MASK     0x7FFFFFFF
//   (ignore last two bits)
#define SHMEM_MASK    0x1FFFFFFFA

// 32 bits (~68GB base cost for native64; ~164GB for mpfr128)
//#define SHMEM_MAXSIZE 0x100000000
//   (standard)
//#define SHMEM_MASK     0xFFFFFFFF
//   (ignore last two bits)
//#define SHMEM_MASK    0x7FFFFFFFA

// hashing function (just a bitmask for now)
//#define SHMEM_HASH(X) ((X) & SHMEM_MASK)

// alternate hash: ignore last two bits (always 0 for dword-aligned data)
#define SHMEM_HASH(X) (((X) & SHMEM_MASK) >> 2)

inline void initMapOpt()
{
    memMapValue = (SH_TYPE*)malloc(sizeof(SH_TYPE) * SHMEM_MAXSIZE);
    memMapValid = (bool*)   calloc(SHMEM_MAXSIZE, sizeof(bool));
    memMapAddr  = (ADDRINT*)malloc(sizeof(ADDRINT) * SHMEM_MAXSIZE);
}

inline size_t calcMapOptSize()
{
    size_t size = 0;
    for (size_t i = 0; i < SHMEM_MAXSIZE; i++) {
        if (memMapValid[i]) {
            size++;
        }
    }
    return size;
}

#define SHMEM_INIT          initMapOpt()
#define SHMEM_ACCESS(X)     (memMapValue[SHMEM_HASH(X)])
#define SHMEM_SET_VALID(X)  memMapValid[SHMEM_HASH(X)] = true; \
                            memMapAddr[SHMEM_HASH(X)] = (X);
#define SHMEM_CLEAR(X)      memMapValid[SHMEM_HASH(X)] = false
#define SHMEM_IS_VALID(X)   (memMapValid[SHMEM_HASH(X)])
#define SHMEM_SIZE          calcMapOptSize()
#define SHMEM_FOR_EACH(X)   for (ADDRINT __a = 0; __a < SHMEM_MAXSIZE; __a++) { \
                                if (!memMapValid[__a]) continue; \
                                (X) = memMapAddr[__a];
#define SHMEM_FINI          free(memMapValue); free(memMapValid); free(memMapAddr)

#endif


/******************************************************************************
 *                            ANALYSIS ROUTINES
 ******************************************************************************/

/*
 * utility method: strip the path out of a filename
 */
inline const char* stripPath(const char *fn)
{
    const char *name = strrchr(fn, '/');
    if (name) {
        return name+1;
    } else {
        return fn;
    }
}

/*
 * run time memory management system -- this keeps us from trying to reference
 * freed memory and also prevents "ghost" shadow values (leftover from now-freed
 * locations) from interfering with new accesses
 */

/*
 * memory region tracker
 */
static unordered_map<ADDRINT, size_t> regions;

/*
 * total amount of memory allocated on the heap
 */
static UINT64 totalHeapBytes = 0;

/*
 * total amount of memory freed
 */
static UINT64 totalHeapBytesFreed = 0;

/*
 * amount of memory requested by allocation call (Pin does not allow us to
 * access function parameters in exit instrumentation so we have to do this in
 * two parts--this could be a challenge to make thread-safe)
 */
static ADDRINT allocSize = 0;

/*
 * previous allocation pointer (used for realloc handling)
 */
static ADDRINT reallocPtr;

/*
 * save allocation call parameters
 */
VOID SHVAL_malloc_entry (ADDRINT size)              { allocSize = size; }
VOID SHVAL_calloc_entry (ADDRINT num, ADDRINT size) { allocSize = num * size; }
VOID SHVAL_realloc_entry(ADDRINT ptr, ADDRINT size) { reallocPtr = ptr;
                                                      allocSize = size; }

/*
 * update memory region tracker: add a new region or update existing regions
 */
VOID SHVAL_malloc_exit(ADDRINT addr)
{
    if (regions.find(addr) != regions.end()) {
        LOG("WARNING - reallocation detected at " + hexstr(addr) + "\n");
        return;
    }
    regions[addr] = allocSize;
    totalHeapBytes += allocSize;
}
VOID SHVAL_calloc_exit(ADDRINT addr)
{
    // probably don't need to implement calloc "set-to-zero" semantics, because
    // reading a zero from memory will trigger a shadow value creation and
    // that's an exact conversion; also, implementing the full semantics would
    // be quite expensive
    //
    SHVAL_malloc_exit(addr);
}
VOID SHVAL_realloc_exit(ADDRINT addr)
{
    if (regions.find(addr) != regions.end()) {
        LOG("WARNING - reallocation detected at " + hexstr(addr) + "\n");
        return;
    }
    if (reallocPtr != 0) {
        ADDRINT oldSize = regions[reallocPtr];
        UINT64 valuesCopied = 0;

        // if a new region was allocated, copy shadow values up to the lesser of
        // the two regions' sizes and erase old values
        if (reallocPtr != addr) {
            ADDRINT limit = (oldSize < allocSize ? oldSize : allocSize);
            // TODO: optimize by incrementing by 4 or 8 instead of 1?
            // (potentially unsafe in the presence of unaligned values)
            for (ADDRINT offset = 0; offset < limit; offset++) {
                ADDRINT oldAddr = reallocPtr + offset;
                ADDRINT newAddr = addr + offset;
                if (SHMEM_IS_VALID(oldAddr)) {
                    SH_ALLOC(SHMEM_ACCESS(newAddr));
                    SH_COPY(SHMEM_ACCESS(newAddr), SHMEM_ACCESS(oldAddr));
                    SH_FREE(SHMEM_ACCESS(oldAddr));
                    SHMEM_CLEAR(oldAddr);
                    valuesCopied++;
                }
            }
        }
        LOG("handled realloc from " + hexstr(reallocPtr) + " (" +
                decstr(oldSize) + " bytes) to " + hexstr(addr) + " (" +
                decstr(allocSize) + " bytes) - " + decstr(valuesCopied) +
                " values copied\n");

        regions.erase(reallocPtr);      // remove old entry
        totalHeapBytes -= oldSize;      // offset by old size
    }
    regions[addr] = allocSize;
    totalHeapBytes += allocSize;
}

/*
 * update memory region tracker: free a region and clear corresponding entries
 * in the shadow value table
 */
VOID SHVAL_free(ADDRINT addr)
{
    if (addr == 0) {
        return;     // free(0) is a nop as per the C99 standard
    }
    if (regions.find(addr) == regions.end()) {
        LOG("WARNING - invalid free() at " + hexstr(addr) + "\n");
        return;
    }
    ADDRINT hi = addr + regions[addr];
    // TODO: optimize by incrementing by 4 or 8 instead of 1?
    // (potentially unsafe in the presence of unaligned values)
    for (ADDRINT mem = addr; mem < hi; mem++) {
        if (SHMEM_IS_VALID(mem)) {
            SH_FREE(SHMEM_ACCESS(mem));
            SHMEM_CLEAR(mem);
        }
    }
    totalHeapBytesFreed += regions[addr];
    regions.erase(addr);
}

/*
 * current effective memory address (stored for verification checking)
 *
 * (needed because Pin won't give addresses to IPOINT_AFTER analysis routines)
 */
static ADDRINT memAddr = 0;

/*
 * save an address (later used in checkShadowValueMem64)
 */
VOID saveMemoryEA(const ADDRINT addr)
{
    memAddr = addr;
}

/*
 * count of runtime errors detected
 */
static UINT64 totalRuntimeErrors = 0;

/*
 * retrieve source code info (this is expensive, so don't do it often)
 */
inline string getSourceInfo(const ADDRINT ins)
{
    PIN_LockClient();
    int line;
    string fn;
    IMG img = IMG_FindByAddress(ins);
    PIN_GetSourceLocation(ins, NULL, &line, &fn);
    PIN_UnlockClient();
    return "[" + (fn != ""
                    ? string(stripPath(fn.c_str())) + ":" + decstr(line)
                    : string(stripPath(IMG_Name(img).c_str()))) + "]";
}

/*
 * checks shadow value at the saved memAddr for correctness
 * (currently only done for native 64-bit analysis)
 */
VOID checkShadowValue(const ADDRINT ins)
{
    double sys = *(double*)memAddr;   // assumes original was 64 bits
    if (SH_ISERR(SHMEM_ACCESS(memAddr), sys)) {
        stringstream shadow("");
        SH_OUTPUT(shadow, SHMEM_ACCESS(memAddr));
        LOG("ONLINE ERROR at 0x" + hexstr(memAddr) + ": sys=" + fltstr(sys,20) +
            " shadow=" + shadow.str() + " ip=" + hexstr(ins) + " " +
            getSourceInfo(ins) + " " + insDisas[ins] + "\n");
        totalRuntimeErrors++;
        if (totalRuntimeErrors > KnobMaximumErrors.Value()) {
            LOG("EXCEEDED ONLINE ERROR LIMIT -- HALTED\n");
            cout << "EXCEEDED ONLINE ERROR LIMIT -- HALTED" << endl;
            exit(-1);
        }
    }
}

/*
 * check shadow value at an XMM register for correctness
 * (currently only checks the first slot; i.e., bits 0-63)
 */
VOID checkShadowReg(UINT32 reg, const PIN_REGISTER *regval, const ADDRINT ins)
{
    DBG_ASSERT(reg < 16);
    double sys = regval->dbl[0];
    if (SH_ISERR(xmm[reg], sys)) {  // slot 0
        double shadow = SH_DBL(xmm[reg]);   // slot 0
        UINT64 sys_u64 = *(UINT64*)&sys;
        UINT64 shadow_u64 = *(UINT64*)&shadow;
        stringstream shstr("");
        SH_OUTPUT(shstr, xmm[reg]);
        LOG("ONLINE ERROR at xmm" + decstr(reg) +
            ": sys=" + fltstr(sys,20) + " [" + hexstr(sys_u64) +
            "] shadow=" + shstr.str() + " [" + hexstr(shadow_u64) +
            "] ip=" + hexstr(ins) + " " + getSourceInfo(ins) + " " +
            insDisas[ins] + "\n");

        totalRuntimeErrors++;
        if (totalRuntimeErrors > KnobMaximumErrors.Value()) {
            LOG("EXCEEDED ONLINE ERROR LIMIT -- HALTED\n");
            cout << "EXCEEDED ONLINE ERROR LIMIT -- HALTED" << endl;
            exit(-1);
        }
    }
}

void dumpMemoryValues(ostream &out, bool dumpAll);

/*
 * shadow value reporting function
 */
VOID reportShadowValues()
{
    if (KnobStdOutShadowDump.Value()) {
        dumpMemoryValues(cout, KnobReportAll.Value());
    } else {
        dumpMemoryValues(outFile, KnobReportAll.Value());
    }
}

/*
 * make sure the shadow value map has an entry for the given address
 */
inline VOID ensureMem32(const ADDRINT mem)
{
    if (!SHMEM_IS_VALID(mem)) {
        SH_ALLOC(SHMEM_ACCESS(mem));
        SH_SET(SHMEM_ACCESS(mem), *(float*)mem);
        SHMEM_SET_VALID(mem);
    }
}

/*
 * make sure the shadow value map has an entry for the given address
 */
inline VOID ensureMem64(const ADDRINT mem)
{
    if (!SHMEM_IS_VALID(mem)) {
        SH_ALLOC(SHMEM_ACCESS(mem));
        SH_SET(SHMEM_ACCESS(mem), *(double*)mem);
        SHMEM_SET_VALID(mem);
    }
}

/*
 * these routines are very similar to ensureMem64, but are split into separate
 * routines to take advantage of Pin-based If/Then instrumentation
 */
ADDRINT shadowMem64IsValid(const ADDRINT mem)
{
    return SHMEM_IS_VALID(mem);
}
ADDRINT shadowMem64IsInvalid(const ADDRINT mem)
{
    return !SHMEM_IS_VALID(mem);
}
VOID shadowMem64Init(const ADDRINT mem)
{
    SH_ALLOC(SHMEM_ACCESS(mem));
    SH_SET(SHMEM_ACCESS(mem), *(double*)mem);
    SHMEM_SET_VALID(mem);
}
VOID shadowMem64InitEmpty(const ADDRINT mem)
{
    SH_ALLOC(SHMEM_ACCESS(mem));
    SHMEM_SET_VALID(mem);
}

/*
 * list of instruction addresses that have overwritten a floating-point value
 */
set<ADDRINT> overwritingInsns;

/*
 * heuristic for determining if a memory address is located on the stack
 */
inline bool isStackAddr(const ADDRINT mem)
{
    return (mem >= 0x7f0000000000);
}

/*
 * handles a non-FP move that could end up writing to a location tracked in our
 * map of FP values -- if this happens, optionally log it (unless it's on the
 * stack, which happens all the time to set up new stack frames and so we don't
 * really care) and erase the map entry
 */
VOID shadowMovToMem64(const ADDRINT ins, const ADDRINT mem)
{
    if (SHMEM_IS_VALID(mem)) {

#if ENABLE_OVERWRITE_LOGGING

        // log the event (NOTE: THIS IS QUITE EXPENSIVE)
        //
        if (!isStackAddr(mem) && overwritingInsns.find(ins) == overwritingInsns.end()) {

            // emit warning
            LOG("WARNING: non-SSE instruction at " + hexstr(ins) +
                " overwrites FP value (e.g. at " + hexstr(mem) + "): "
                + getSourceInfo(ins) + " " + insDisas[ins] + "\n");

            // tag this instruction so we don't log it again
            overwritingInsns.insert(ins);
        }
#endif

        // clear the table
        SH_FREE(SHMEM_ACCESS(mem));
        SHMEM_CLEAR(mem);
    }
}

/*
 * similar to above function but is streamlined so that If/Then instrumentation
 * can be inserted more efficiently (similar to ensureMem64)
 */
VOID shadowClearMem64(const ADDRINT mem)
{
    SH_FREE(SHMEM_ACCESS(mem));
    SHMEM_CLEAR(mem);
}

/*
 * packed version of above routine (calls it twice; Pin will probably inline
 * these calls) -- this pattern is typical of the other analysis routines below
 */
VOID shadowMovPackedToMem64(const ADDRINT ins, const ADDRINT mem)
{
    shadowMovToMem64(ins, mem);
    shadowMovToMem64(ins, mem+8);
}

/*
 * reset shadow values for a register -- handles cases where the compiler may
 * use 32-bit or integer instructions to manipulate 64-bit floating-point
 * values
 */
VOID shadowResetReg64(UINT32 reg, const PIN_REGISTER *sreg)
{
    SH_SET(xmm[XMM_SLOT(reg,0)], sreg->dbl[0]);
}
VOID shadowResetPackedReg64(UINT32 reg, const PIN_REGISTER *sreg)
{
    SH_SET(xmm[XMM_SLOT(reg,0)], sreg->dbl[0]);
    SH_SET(xmm[XMM_SLOT(reg,2)], sreg->dbl[1]);
}

/*
 * These are routines to update shadow values in various combinations. They
 * could probably be written in more general ways, but they are intended to be
 * highly optimized by the compiler and Pin. For that reason, they are split
 * into many different routines that do a very specific operation. Code is
 * reused wherever possible, but there's still a lot of copy/paste with minor
 * changes.
 *
 * WARNING: HERE BE MACROS! :)
 */

VOID shadowMovScalarMem32ToReg32(const ADDRINT mem, UINT32 reg)
{
    DBG_ASSERT(reg < 16);
    ensureMem32(mem);
    SH_COPY(xmm[reg], SHMEM_ACCESS(mem));
}

VOID shadowMovScalarReg32ToMem32(UINT32 reg, const ADDRINT mem)
{
    DBG_ASSERT(reg < 16);
    ensureMem32(mem);
    SH_COPY(SHMEM_ACCESS(mem), xmm[reg]);
}

VOID shadowMovScalarGPR32ToReg32(const PIN_REGISTER *sreg, UINT32 dreg)
{
    DBG_ASSERT(dreg < 16);
    SH_SET(xmm[dreg], sreg->flt[0]);
}

VOID shadowMovScalarReg32ToReg32(UINT32 sreg, UINT32 dreg)
{
    DBG_ASSERT(sreg < 16 && dreg < 16);
    SH_COPY(xmm[dreg], xmm[sreg]);
}

VOID shadowMovPackedMem32ToReg32(const ADDRINT mem, UINT32 reg)
{
    DBG_ASSERT(reg < 16);
    //ensureMem32(mem);
    ensureMem64(mem);
    //ensureMem32(mem+4);       // TODO: re-enable 32-bit slot handling
    //ensureMem32(mem+8);       // (causes bogus shadow values for 64-bit instructions!)
    ensureMem64(mem+8);
    //ensureMem32(mem+12);
    SH_COPY(xmm[XMM_SLOT(reg,0)], SHMEM_ACCESS(mem));
    //SH_COPY(xmm[XMM_SLOT(reg,1)], SHMEM_ACCESS(mem+4));
    SH_COPY(xmm[XMM_SLOT(reg,2)], SHMEM_ACCESS(mem+8));
    //SH_COPY(xmm[XMM_SLOT(reg,3)], SHMEM_ACCESS(mem+12));
}

VOID shadowMovPackedReg32ToMem32(UINT32 reg, const ADDRINT mem)
{
    DBG_ASSERT(reg < 16);
    //ensureMem32(mem);
    ensureMem64(mem);
    //ensureMem32(mem+4);       // TODO: re-enable 32-bit slot handling
    //ensureMem32(mem+8);       // (causes bogus shadow values for 64-bit instructions!)
    ensureMem64(mem+8);
    //ensureMem32(mem+12);
    SH_COPY(SHMEM_ACCESS(mem),    xmm[XMM_SLOT(reg,0)]);
    //SH_COPY(SHMEM_ACCESS(mem+4),  xmm[XMM_SLOT(reg,1)]);
    SH_COPY(SHMEM_ACCESS(mem+8),  xmm[XMM_SLOT(reg,2)]);
    //SH_COPY(SHMEM_ACCESS(mem+12), xmm[XMM_SLOT(reg,3)]);
}

VOID shadowMovPackedReg32ToReg32(UINT32 sreg, UINT32 dreg)
{
    DBG_ASSERT(sreg < 16 && dreg < 16);
    SH_COPY(xmm[XMM_SLOT(dreg,0)], xmm[XMM_SLOT(sreg,0)]);
    SH_COPY(xmm[XMM_SLOT(dreg,1)], xmm[XMM_SLOT(sreg,1)]);
    SH_COPY(xmm[XMM_SLOT(dreg,2)], xmm[XMM_SLOT(sreg,2)]);
    SH_COPY(xmm[XMM_SLOT(dreg,3)], xmm[XMM_SLOT(sreg,3)]);
}

VOID shadowMovScalarMem64ToReg64(const ADDRINT mem, UINT32 reg)
{
    DBG_ASSERT(reg < 16);
    SH_COPY(xmm[reg], SHMEM_ACCESS(mem));
}

VOID shadowMovScalarReg64ToMem64(UINT32 reg, const ADDRINT mem)
{
    DBG_ASSERT(reg < 16);
    SH_COPY(SHMEM_ACCESS(mem), xmm[reg]);
}

VOID shadowMovScalarGPR64ToReg64(const PIN_REGISTER *sreg, UINT32 dreg)
{
    DBG_ASSERT(dreg < 16);
    SH_SET(xmm[dreg], sreg->dbl[0]);
}

VOID shadowMovScalarReg64ToReg64(UINT32 sreg, UINT32 dreg)
{
    DBG_ASSERT(sreg < 16 && dreg < 16);
    SH_COPY(xmm[dreg], xmm[sreg]);
}

VOID shadowMovPackedMem64ToReg64(const ADDRINT mem, UINT32 reg)
{
    DBG_ASSERT(reg < 16);
    ensureMem64(mem+8);
    SH_COPY(xmm[XMM_SLOT(reg,0)], SHMEM_ACCESS(mem));
    SH_COPY(xmm[XMM_SLOT(reg,2)], SHMEM_ACCESS(mem+8));
}

VOID shadowMovPackedReg64ToMem64(UINT32 reg, const ADDRINT mem)
{
    DBG_ASSERT(reg < 16);
    ensureMem64(mem+8);
    SH_COPY(SHMEM_ACCESS(mem), xmm[XMM_SLOT(reg,0)]);
    SH_COPY(SHMEM_ACCESS(mem+8), xmm[XMM_SLOT(reg,2)]);
}

VOID shadowMovPackedReg64ToReg64(UINT32 sreg, UINT32 dreg)
{
    DBG_ASSERT(sreg < 16 && dreg < 16);
    SH_COPY(xmm[XMM_SLOT(dreg,0)], xmm[XMM_SLOT(sreg,0)]);
    SH_COPY(xmm[XMM_SLOT(dreg,2)], xmm[XMM_SLOT(sreg,2)]);
}

VOID shadowMovHighMem64ToReg64(const ADDRINT mem, UINT32 reg)
{
    DBG_ASSERT(reg < 16);
    SH_COPY(xmm[XMM_SLOT(reg,2)], SHMEM_ACCESS(mem));
}

VOID shadowMovHighReg64ToMem64(UINT32 reg, const ADDRINT mem)
{
    DBG_ASSERT(reg < 16);
    SH_COPY(SHMEM_ACCESS(mem), xmm[XMM_SLOT(reg,2)]);
}

VOID shadowMovHighReg64ToReg64(UINT32 sreg, UINT32 dreg)
{
    DBG_ASSERT(sreg < 16 && dreg < 16);
    SH_COPY(xmm[XMM_SLOT(dreg,2)], xmm[XMM_SLOT(sreg,2)]);
}

VOID shadowSHUFPD(UINT32 dreg, UINT32 sreg, UINT32 imm)
{
    DBG_ASSERT(dreg < 16 && sreg < 16);
    if (dreg == sreg && imm == 1) {
        // special semantics; swap two packed values in the same register
        SH_TYPE tmp;
        SH_ALLOC(tmp);
        SH_COPY(tmp, xmm[XMM_SLOT(dreg, 0)]);
        SH_COPY(xmm[XMM_SLOT(dreg, 0)], xmm[XMM_SLOT(dreg, 2)]);
        SH_COPY(xmm[XMM_SLOT(dreg, 2)], tmp);
        SH_FREE(tmp);
    } else {
        SH_COPY(xmm[XMM_SLOT(dreg, 0)], xmm[XMM_SLOT(dreg, (imm & 0x1)*2)]);
        SH_COPY(xmm[XMM_SLOT(dreg, 2)], xmm[XMM_SLOT(sreg, (imm & 0x2))]);
    }
}

VOID shadowUNPCKLPD(UINT32 reg1, UINT32 reg2)
{   SH_COPY(xmm[XMM_SLOT(reg1,0)], xmm[XMM_SLOT(reg1,0)]);
    SH_COPY(xmm[XMM_SLOT(reg1,2)], xmm[XMM_SLOT(reg2,0)]); }

VOID shadowUNPCKHPD(UINT32 reg1, UINT32 reg2)
{   SH_COPY(xmm[XMM_SLOT(reg1,0)], xmm[XMM_SLOT(reg1,2)]);
    SH_COPY(xmm[XMM_SLOT(reg1,2)], xmm[XMM_SLOT(reg2,2)]); }

VOID shadowUNPCKLPS(UINT32 reg1, UINT32 reg2)
{   SH_COPY(xmm[XMM_SLOT(reg1,0)], xmm[XMM_SLOT(reg1,0)]);
    SH_COPY(xmm[XMM_SLOT(reg1,1)], xmm[XMM_SLOT(reg2,0)]);
    SH_COPY(xmm[XMM_SLOT(reg1,2)], xmm[XMM_SLOT(reg1,1)]);
    SH_COPY(xmm[XMM_SLOT(reg1,3)], xmm[XMM_SLOT(reg2,1)]); }

VOID shadowUNPCKHPS(UINT32 reg1, UINT32 reg2)
{   SH_COPY(xmm[XMM_SLOT(reg1,0)], xmm[XMM_SLOT(reg1,2)]);
    SH_COPY(xmm[XMM_SLOT(reg1,1)], xmm[XMM_SLOT(reg2,2)]);
    SH_COPY(xmm[XMM_SLOT(reg1,2)], xmm[XMM_SLOT(reg1,3)]);
    SH_COPY(xmm[XMM_SLOT(reg1,3)], xmm[XMM_SLOT(reg2,3)]); }

VOID shadowMOVDDUP(UINT32 reg1, UINT32 reg2)
{   SH_COPY(xmm[XMM_SLOT(reg1,0)], xmm[XMM_SLOT(reg2,0)]);
    SH_COPY(xmm[XMM_SLOT(reg1,2)], xmm[XMM_SLOT(reg2,0)]); }

VOID shadowADDSD_Mem64(UINT32 reg, const ADDRINT mem)
{ SH_ADD(xmm[reg], SHMEM_ACCESS(mem)); }
VOID shadowSUBSD_Mem64(UINT32 reg, const ADDRINT mem)
{ SH_SUB(xmm[reg], SHMEM_ACCESS(mem)); }
VOID shadowMULSD_Mem64(UINT32 reg, const ADDRINT mem)
{ SH_MUL(xmm[reg], SHMEM_ACCESS(mem)); }
VOID shadowDIVSD_Mem64(UINT32 reg, const ADDRINT mem)
{ SH_DIV(xmm[reg], SHMEM_ACCESS(mem)); }
VOID shadowMINSD_Mem64(UINT32 reg, const ADDRINT mem)
{ SH_MIN(xmm[reg], SHMEM_ACCESS(mem)); }
VOID shadowMAXSD_Mem64(UINT32 reg, const ADDRINT mem)
{ SH_MAX(xmm[reg], SHMEM_ACCESS(mem)); }
VOID shadowSQRTSD_Mem64(UINT32 reg, const ADDRINT mem)
{ SH_SQRT(xmm[reg], SHMEM_ACCESS(mem)); }
VOID shadowRNDSD_Mem64(UINT32 reg, const ADDRINT mem)
{ SH_RND(xmm[reg], SHMEM_ACCESS(mem)); }

VOID shadowADDSD(UINT32 reg1, UINT32 reg2) { SH_ADD(xmm[reg1], xmm[reg2]); }
VOID shadowSUBSD(UINT32 reg1, UINT32 reg2) { SH_SUB(xmm[reg1], xmm[reg2]); }
VOID shadowMULSD(UINT32 reg1, UINT32 reg2) { SH_MUL(xmm[reg1], xmm[reg2]); }
VOID shadowDIVSD(UINT32 reg1, UINT32 reg2) { SH_DIV(xmm[reg1], xmm[reg2]); }
VOID shadowMINSD(UINT32 reg1, UINT32 reg2) { SH_MIN(xmm[reg1], xmm[reg2]); }
VOID shadowMAXSD(UINT32 reg1, UINT32 reg2) { SH_MAX(xmm[reg1], xmm[reg2]); }
VOID shadowSQRTSD(UINT32 reg1, UINT32 reg2){ SH_SQRT(xmm[reg1],xmm[reg2]); }
VOID shadowRNDSD(UINT32 reg1, UINT32 reg2) { SH_RND(xmm[reg1], xmm[reg2]); }

VOID shadowADDPD_Mem64(UINT32 reg, const ADDRINT mem)
{   ensureMem64(mem+8);
    SH_ADD(xmm[XMM_SLOT(reg,0)], SHMEM_ACCESS(mem));
    SH_ADD(xmm[XMM_SLOT(reg,2)], SHMEM_ACCESS(mem+8)); }
VOID shadowSUBPD_Mem64(UINT32 reg, const ADDRINT mem)
{   ensureMem64(mem+8);
    SH_SUB(xmm[XMM_SLOT(reg,0)], SHMEM_ACCESS(mem));
    SH_SUB(xmm[XMM_SLOT(reg,2)], SHMEM_ACCESS(mem+8)); }
VOID shadowMULPD_Mem64(UINT32 reg, const ADDRINT mem)
{   ensureMem64(mem+8);
    SH_MUL(xmm[XMM_SLOT(reg,0)], SHMEM_ACCESS(mem));
    SH_MUL(xmm[XMM_SLOT(reg,2)], SHMEM_ACCESS(mem+8)); }
VOID shadowDIVPD_Mem64(UINT32 reg, const ADDRINT mem)
{   ensureMem64(mem+8);
    SH_DIV(xmm[XMM_SLOT(reg,0)], SHMEM_ACCESS(mem));
    SH_DIV(xmm[XMM_SLOT(reg,2)], SHMEM_ACCESS(mem+8)); }
VOID shadowMINPD_Mem64(UINT32 reg, const ADDRINT mem)
{   ensureMem64(mem+8);
    SH_MIN(xmm[XMM_SLOT(reg,0)], SHMEM_ACCESS(mem));
    SH_MIN(xmm[XMM_SLOT(reg,2)], SHMEM_ACCESS(mem+8)); }
VOID shadowMAXPD_Mem64(UINT32 reg, const ADDRINT mem)
{   ensureMem64(mem+8);
    SH_MAX(xmm[XMM_SLOT(reg,0)], SHMEM_ACCESS(mem));
    SH_MAX(xmm[XMM_SLOT(reg,2)], SHMEM_ACCESS(mem+8)); }
VOID shadowSQRTPD_Mem64(UINT32 reg, const ADDRINT mem)
{   ensureMem64(mem+8);
    SH_SQRT(xmm[XMM_SLOT(reg,0)], SHMEM_ACCESS(mem));
    SH_SQRT(xmm[XMM_SLOT(reg,2)], SHMEM_ACCESS(mem+8)); }
VOID shadowRNDPD_Mem64(UINT32 reg, const ADDRINT mem)
{   ensureMem64(mem+8);
    SH_RND(xmm[XMM_SLOT(reg,0)], SHMEM_ACCESS(mem));
    SH_RND(xmm[XMM_SLOT(reg,2)], SHMEM_ACCESS(mem+8)); }

VOID shadowADDPD(UINT32 reg1, UINT32 reg2)
{ SH_ADD(xmm[XMM_SLOT(reg1,0)], xmm[XMM_SLOT(reg2,0)]);
  SH_ADD(xmm[XMM_SLOT(reg1,2)], xmm[XMM_SLOT(reg2,2)]); }
VOID shadowSUBPD(UINT32 reg1, UINT32 reg2)
{ SH_SUB(xmm[XMM_SLOT(reg1,0)], xmm[XMM_SLOT(reg2,0)]);
  SH_SUB(xmm[XMM_SLOT(reg1,2)], xmm[XMM_SLOT(reg2,2)]); }
VOID shadowMULPD(UINT32 reg1, UINT32 reg2)
{ SH_MUL(xmm[XMM_SLOT(reg1,0)], xmm[XMM_SLOT(reg2,0)]);
  SH_MUL(xmm[XMM_SLOT(reg1,2)], xmm[XMM_SLOT(reg2,2)]); }
VOID shadowDIVPD(UINT32 reg1, UINT32 reg2)
{ SH_DIV(xmm[XMM_SLOT(reg1,0)], xmm[XMM_SLOT(reg2,0)]);
  SH_DIV(xmm[XMM_SLOT(reg1,2)], xmm[XMM_SLOT(reg2,2)]); }
VOID shadowMINPD(UINT32 reg1, UINT32 reg2)
{ SH_MIN(xmm[XMM_SLOT(reg1,0)], xmm[XMM_SLOT(reg2,0)]);
  SH_MIN(xmm[XMM_SLOT(reg1,2)], xmm[XMM_SLOT(reg2,2)]); }
VOID shadowMAXPD(UINT32 reg1, UINT32 reg2)
{ SH_MAX(xmm[XMM_SLOT(reg1,0)], xmm[XMM_SLOT(reg2,0)]);
  SH_MAX(xmm[XMM_SLOT(reg1,2)], xmm[XMM_SLOT(reg2,2)]); }
VOID shadowSQRTPD(UINT32 reg1, UINT32 reg2)
{ SH_SQRT(xmm[XMM_SLOT(reg1,0)], xmm[XMM_SLOT(reg2,0)]);
  SH_SQRT(xmm[XMM_SLOT(reg1,2)], xmm[XMM_SLOT(reg2,2)]); }
VOID shadowRNDPD(UINT32 reg1, UINT32 reg2)
{ SH_RND(xmm[XMM_SLOT(reg1,0)], xmm[XMM_SLOT(reg2,0)]);
  SH_RND(xmm[XMM_SLOT(reg1,2)], xmm[XMM_SLOT(reg2,2)]); }

// TODO: other 32-bit floating-point instructions (currently unsupported)
VOID shadowADDPS(UINT32 reg1, UINT32 reg2)
{
    SH_ADD(xmm[XMM_SLOT(reg1,0)], xmm[XMM_SLOT(reg2,0)]);
    SH_ADD(xmm[XMM_SLOT(reg1,1)], xmm[XMM_SLOT(reg2,1)]);
    SH_ADD(xmm[XMM_SLOT(reg1,2)], xmm[XMM_SLOT(reg2,2)]);
    SH_ADD(xmm[XMM_SLOT(reg1,3)], xmm[XMM_SLOT(reg2,3)]);
}

VOID shadowCVTSI2SD_Mem64(const ADDRINT mem, UINT32 dreg)
{
    DBG_ASSERT(dreg < 16);
    SH_SET(xmm[dreg], (double)(*(INT32*)mem));
}

VOID shadowCVTSI642SD_Mem64(const ADDRINT mem, UINT32 dreg)
{
    DBG_ASSERT(dreg < 16);
    SH_SET(xmm[dreg], (double)(*(INT64*)mem));
}

VOID shadowCVTSI2SD(const PIN_REGISTER *sreg, UINT32 dreg)
{
    DBG_ASSERT(dreg < 16);
    SH_SET(xmm[dreg], (double)(*(INT32*)&sreg->dword[0]));
}

VOID shadowCVTSI642SD(const PIN_REGISTER *sreg, UINT32 dreg)
{
    DBG_ASSERT(dreg < 16);
    SH_SET(xmm[dreg], (double)(*(INT64*)&sreg->dword[0]));
}

VOID shadowCVTSS2SD_Mem64(const ADDRINT mem, UINT32 dreg)
{
    DBG_ASSERT(dreg < 16);
    SH_SET(xmm[dreg], (double)(*(float*)mem));
}

VOID shadowCVTSS2SD(const PIN_REGISTER *sreg, UINT32 dreg)
{
    DBG_ASSERT(dreg < 16);
    SH_SET(xmm[dreg], (double)sreg->flt[0]);
}

VOID shadowCVTPS2PD_Mem64(const ADDRINT mem, UINT32 dreg)
{
    DBG_ASSERT(dreg < 16);
    SH_SET(xmm[XMM_SLOT(dreg,0)], (double)(*(float*)mem));
    SH_SET(xmm[XMM_SLOT(dreg,2)], (double)(*(float*)mem+4));
}

VOID shadowCVTPS2PD(const PIN_REGISTER *sreg, UINT32 dreg)
{
    DBG_ASSERT(dreg < 16);
    SH_SET(xmm[XMM_SLOT(dreg,0)], (double)sreg->flt[0]);
    SH_SET(xmm[XMM_SLOT(dreg,2)], (double)sreg->flt[1]);
}


VOID shadowCVTDQ2PD_Mem64(const ADDRINT mem, UINT32 dreg)
{
    DBG_ASSERT(dreg < 16);
    SH_SET(xmm[XMM_SLOT(dreg,0)], (double)(*(INT32*)mem));
    SH_SET(xmm[XMM_SLOT(dreg,2)], (double)(*(INT32*)(mem+4)));
}

VOID shadowCVTDQ2PD(const PIN_REGISTER *sreg, UINT32 dreg)
{
    DBG_ASSERT(dreg < 16);
    SH_SET(xmm[XMM_SLOT(dreg,0)], (double)(*(INT32*)&sreg->dword[0]));
    SH_SET(xmm[XMM_SLOT(dreg,2)], (double)(*(INT32*)&sreg->dword[1]));
}


/*
 * HACK WARNING! :)
 *
 * The following analysis routines are custom workarounds for particular idioms
 * seen "in the wild" where a bitwise instruction is used to modify a
 * floating-point value (often involving the manipulation of the sign bit).
 * Unfortunately there seems to be no general way to deal with these situations;
 * we currently implement the semantics manually at runtime, which is expensive.
 * Some of it could potentially be optimized with better static analysis.
 */

/*
 * utility method: clear extra 32-bit shadow value slots (used during 128-bit
 * instructions like PXOR to clear register slots that might later be
 * interpreted as 32-bit values)
 */
inline void shadowClearReg32SlotsReg64(UINT32 reg)
{
    SH_SET(xmm[XMM_SLOT(reg,1)], 0.0);
    SH_SET(xmm[XMM_SLOT(reg,3)], 0.0);
}

/*
 * keep track of instructions with non-semantic bitwise operations so that we
 * don't have to report every execution
 */
set<ADDRINT> nonSemanticInsns;

inline void logNonSemanticInsn(ADDRINT ins, UINT64 val1, UINT val2, string op)
{
    if (nonSemanticInsns.find(ins) == nonSemanticInsns.end()) {
        LOG("WARNING - non-semantic bitwise case at instruction " + hexstr(ins) +
                " (e.g., " + hexstr(val1) + op + hexstr(val2) + ")\n");
        nonSemanticInsns.insert(ins);
    }
}

inline void shadowAND64(ADDRINT ins, SH_TYPE* shv1, SH_TYPE* shv2, UINT64 val1, UINT64 val2)
{
    if (val1 == 0 || val2 == 0) {    // set to zero
        SH_SET(*shv1, 0.0);
    } else if (val1 == 0xffffffffffffffff) { // preserve val2
        SH_COPY(*shv1, *shv2);
    } else if (val2 == 0xffffffffffffffff) { // preserve val1
        // nop?
    } else if (val1 == 0x7fffffffffffffff) { // absolute value of val2
        SH_ABS(*shv1, *shv2);
    } else if (val2 == 0x7fffffffffffffff) { // absolute value of val2
        SH_ABS(*shv1, *shv1);
    } else {
        UINT64 result = val1 & val2;
        SH_SET(*shv1, *(double*)&result);
        logNonSemanticInsn(ins, val1, val2, " & ");
    }
}

VOID shadowANDPD(ADDRINT ins, UINT32 reg1, UINT32 reg2,
        const PIN_REGISTER *reg1v, const PIN_REGISTER *reg2v)
{
    DBG_ASSERT(reg1 < 16 && reg2 < 16);
    shadowAND64(ins, &xmm[XMM_SLOT(reg1,0)], &xmm[XMM_SLOT(reg2,0)], reg1v->qword[0], reg2v->qword[0]);
    shadowAND64(ins, &xmm[XMM_SLOT(reg1,2)], &xmm[XMM_SLOT(reg2,2)], reg1v->qword[1], reg2v->qword[1]);
    shadowClearReg32SlotsReg64(reg1);     // for PAND
}

VOID shadowANDPD_Mem64(ADDRINT ins, UINT32 reg, const PIN_REGISTER *regv, const ADDRINT mem)
{
    DBG_ASSERT(reg < 16);
    ensureMem64(mem);
    ensureMem64(mem+8);
    shadowAND64(ins, &xmm[XMM_SLOT(reg,0)], &SHMEM_ACCESS(mem),   regv->qword[0], *(UINT64*)(mem));
    shadowAND64(ins, &xmm[XMM_SLOT(reg,2)], &SHMEM_ACCESS(mem+8), regv->qword[1], *(UINT64*)(mem+8));
    shadowClearReg32SlotsReg64(reg);      // for PAND
}

VOID shadowANDNPD(ADDRINT ins, UINT32 reg1, UINT32 reg2,
        const PIN_REGISTER *reg1v, const PIN_REGISTER *reg2v)
{
    DBG_ASSERT(reg1 < 16 && reg2 < 16);
    shadowAND64(ins, &xmm[XMM_SLOT(reg1,0)], &xmm[XMM_SLOT(reg2,0)], ~reg1v->qword[0], ~reg2v->qword[0]);
    shadowAND64(ins, &xmm[XMM_SLOT(reg1,2)], &xmm[XMM_SLOT(reg2,2)], ~reg1v->qword[1], ~reg2v->qword[1]);
    shadowClearReg32SlotsReg64(reg1);     // for PANDN
}

VOID shadowANDNPD_Mem64(ADDRINT ins, UINT32 reg, const PIN_REGISTER *regv, const ADDRINT mem)
{
    DBG_ASSERT(reg < 16);
    ensureMem64(mem);
    ensureMem64(mem+8);
    shadowAND64(ins, &xmm[XMM_SLOT(reg,0)], &SHMEM_ACCESS(mem),   ~regv->qword[0], ~(*(UINT64*)(mem)));
    shadowAND64(ins, &xmm[XMM_SLOT(reg,2)], &SHMEM_ACCESS(mem+8), ~regv->qword[1], ~(*(UINT64*)(mem+8)));
    shadowClearReg32SlotsReg64(reg);      // for ANDN
}

inline void shadowOR64(ADDRINT ins, SH_TYPE* shv1, SH_TYPE* shv2, UINT64 val1, UINT64 val2)
{
    if (val1 == 0) { // preserve val2
        SH_COPY(*shv1, *shv2);
    } else if (val2 == 0) { // preserve val1
        // nop?
    } else {
        UINT64 result = val1 | val2;
        SH_SET(*shv1, *(double*)&result);
        logNonSemanticInsn(ins, val1, val2, " | ");
    }
}

VOID shadowORPD(ADDRINT ins, UINT32 reg1, UINT32 reg2,
        const PIN_REGISTER *reg1v, const PIN_REGISTER *reg2v)
{
    DBG_ASSERT(reg1 < 16);
    shadowOR64(ins, &xmm[XMM_SLOT(reg1,0)], &xmm[XMM_SLOT(reg2,0)], reg1v->qword[0], reg2v->qword[0]);
    shadowOR64(ins, &xmm[XMM_SLOT(reg1,2)], &xmm[XMM_SLOT(reg2,2)], reg1v->qword[1], reg2v->qword[1]);
    shadowClearReg32SlotsReg64(reg1);     // for POR
}

VOID shadowORPD_Mem64(ADDRINT ins, UINT32 reg, const PIN_REGISTER *regv, const ADDRINT mem)
{
    DBG_ASSERT(reg < 16);
    ensureMem64(mem);
    ensureMem64(mem+8);
    shadowOR64(ins, &xmm[XMM_SLOT(reg,0)], &SHMEM_ACCESS(mem),   regv->qword[0], *(UINT64*)(mem));
    shadowOR64(ins, &xmm[XMM_SLOT(reg,2)], &SHMEM_ACCESS(mem+8), regv->qword[1], *(UINT64*)(mem+8));
    shadowClearReg32SlotsReg64(reg);      // for POR
}

inline void shadowXOR64(ADDRINT ins, SH_TYPE* shv1, SH_TYPE* shv2, UINT64 val1, UINT64 val2)
{
    if (val1 == val2) {     // set to zero
        SH_SET(*shv1, 0.0);
    } else if (val1 == 0x8000000000000000) { // negate val2
        SH_NEG(*shv1, *shv2);
    } else if (val2 == 0x8000000000000000) { // negate val1
        SH_NEG(*shv1, *shv1);
    } else {
        UINT64 result = val1 ^ val2;
        SH_SET(*shv1, *(double*)&result);
        logNonSemanticInsn(ins, val1, val2, " ^ ");
    }
}

VOID shadowXORPD(ADDRINT ins, UINT32 reg1, UINT32 reg2,
        const PIN_REGISTER *reg1v, const PIN_REGISTER *reg2v)
{
    DBG_ASSERT(reg1 < 16 && reg2 < 16);
    shadowXOR64(ins, &xmm[XMM_SLOT(reg1,0)], &xmm[XMM_SLOT(reg2,0)], reg1v->qword[0], reg2v->qword[0]);
    shadowXOR64(ins, &xmm[XMM_SLOT(reg1,2)], &xmm[XMM_SLOT(reg2,2)], reg1v->qword[1], reg2v->qword[1]);
    shadowClearReg32SlotsReg64(reg1);     // for PXOR
}

VOID shadowXORPD_Mem64(ADDRINT ins, UINT32 reg, const PIN_REGISTER *regv, const ADDRINT mem)
{
    DBG_ASSERT(reg < 16);
    ensureMem64(mem);
    ensureMem64(mem+8);
    shadowXOR64(ins, &xmm[XMM_SLOT(reg,0)], &SHMEM_ACCESS(mem),   regv->qword[0], *(UINT64*)(mem));
    shadowXOR64(ins, &xmm[XMM_SLOT(reg,2)], &SHMEM_ACCESS(mem+8), regv->qword[1], *(UINT64*)(mem+8));
    shadowClearReg32SlotsReg64(reg);      // for PXOR
}


#if USE_MPI

/******************************************************************************
 *                              MPI DATA MOVEMENT
 ******************************************************************************/

typedef struct {
    double  sys;
    SH_PACKED_TYPE shv;
} mpiPackedValue;

/*
 * pointers to MPI functions
 */
static AFUNPTR mpiCommRankPtr;
static AFUNPTR mpiCommSizePtr;

/*
 * allocate temporary array of shadow values for MPI communication
 */
inline mpiPackedValue* shadowMPIAlloc(int count)
{
    mpiPackedValue *dest = (mpiPackedValue*)malloc(sizeof(mpiPackedValue) * count);
    assert(dest != NULL);
    return dest;
}

/*
 * de-allocate temporary array
 */
inline void shadowMPIFree(mpiPackedValue *src, int count)
{
    free(src);
}

/*
 * allocate and pack temporary array of shadow values for MPI communication
 */
inline mpiPackedValue* shadowMPIPack(void *src, int count)
{
    mpiPackedValue *dest = shadowMPIAlloc(count);
    ADDRINT addr = (ADDRINT)src;
    for (int i = 0; i < count; i++) {
        dest[i].sys = *(double*)addr;
        ensureMem64(addr);
        SH_PACK(dest[i].shv, SHMEM_ACCESS(addr));
        addr += 8;
    }
    return dest;
}

/*
 * unpack and de-allocate temporary array into shadow value table
 */
inline void shadowMPIUnpack(void *dest, mpiPackedValue *src, int count)
{
    ADDRINT addr = (ADDRINT)dest;
    for (int i = 0; i < count; i++) {
        *(double*)addr = src[i].sys;
        if (!SHMEM_IS_VALID(addr)) {
            SH_ALLOC(SHMEM_ACCESS(addr));
            SHMEM_SET_VALID(addr);
        }
        SH_UNPACK(SHMEM_ACCESS(addr), src[i].shv);
        //SH_SET(SHMEM_ACCESS(addr), 0.0);    // for testing
        addr += 8;
    }
    shadowMPIFree(src, count);
}

/*
 * get the rank and size of the given communicator (used for some communication
 * wrappers)
 */
inline int getMPICommRankSize(const CONTEXT *ctx, THREADID tid,
        MPI_Comm comm, int *rank, int *size)
{
    int rval;
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, mpiCommRankPtr, NULL,
            PIN_PARG(int),          &rval,
            PIN_PARG(MPI_Comm),     comm,
            PIN_PARG(int*),         rank,
            PIN_PARG_END());
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, mpiCommSizePtr, NULL,
            PIN_PARG(int),          &rval,
            PIN_PARG(MPI_Comm),     comm,
            PIN_PARG(int*),         size,
            PIN_PARG_END());
    return rval;
}

/*
 * info about a non-blocking operations, stored so that the shadow values can be
 * unpacked when the operation finishes
 */
typedef struct {
    bool send;
    void *buf;
    mpiPackedValue *tmp;
    int count;
} mpiNonBlockOp;

/*
 * lookup table: maps MPI_Requests to corresponding shadow value information
 * (used to clean up during the corresponding MPI_Wait calls)
 */
std::unordered_map<MPI_Request,mpiNonBlockOp> nonblockingOps;

/*
 * MPI wrappers
 */

int shadowMPISend(const CONTEXT *ctx, THREADID tid, AFUNPTR origFunPtr,
        void *buf, int count, MPI_Datatype dt, int dest, int tag, MPI_Comm comm)
{
    int rval;   // return value

    // if double precision, pack and send shadow values too
    if (dt == MPI_DOUBLE || dt == MPI_DOUBLE_PRECISION) {
        //printf("Shadowing MPI_Send (count=%d, dest=%d, tag=%d)\n", count, dest, tag);
        mpiPackedValue *tmp = shadowMPIPack(buf, count);
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        tmp,
                PIN_PARG(int),          count * sizeof(mpiPackedValue),
                PIN_PARG(MPI_Datatype), MPI_BYTE,
                PIN_PARG(int),          dest,
                PIN_PARG(int),          tag,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());
        shadowMPIFree(tmp, count);

    // otherwise, just call MPI_Send with original parameters
    } else {
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        buf,
                PIN_PARG(int),          count,
                PIN_PARG(MPI_Datatype), dt,
                PIN_PARG(int),          dest,
                PIN_PARG(int),          tag,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());
    }
    return rval;
}

int shadowMPIRecv(const CONTEXT *ctx, THREADID tid, AFUNPTR origFunPtr,
        void *buf, int count, MPI_Datatype dt, int src, int tag, MPI_Comm comm, MPI_Status *status)
{
    int rval;   // return value

    // if double precision, receive and unpack shadow data too
    if (dt == MPI_DOUBLE || dt == MPI_DOUBLE_PRECISION) {
        //printf("Shadowing MPI_Recv (count=%d, src=%d, tag=%d)\n", count, src, tag);
        mpiPackedValue *tmp = shadowMPIAlloc(count);
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        tmp,
                PIN_PARG(int),          count * sizeof(mpiPackedValue),
                PIN_PARG(MPI_Datatype), MPI_BYTE,
                PIN_PARG(int),          src,
                PIN_PARG(int),          tag,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG(MPI_Status*),  NULL,
                PIN_PARG_END());
        shadowMPIUnpack(buf, tmp, count);

    // otherwise, just call MPI_Recv with original parameters
    } else {
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        buf,
                PIN_PARG(int),          count,
                PIN_PARG(MPI_Datatype), dt,
                PIN_PARG(int),          src,
                PIN_PARG(int),          tag,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG(MPI_Status*),  status,
                PIN_PARG_END());
    }
    return rval;
}

int shadowMPISendrecv(const CONTEXT *ctx, THREADID tid, AFUNPTR origFunPtr,
        void *send_buf, int send_count, MPI_Datatype send_dt, int dest,   int send_tag,
        void *recv_buf, int recv_count, MPI_Datatype recv_dt, int source, int recv_tag,
        MPI_Comm comm, MPI_Status *status)
{
    int rval;   // return value

    // if double precision, pack and send shadow values too
    if (send_dt == MPI_DOUBLE || send_dt == MPI_DOUBLE_PRECISION) {
        //printf("Shadowing MPI_Sendrecv (count=%d, tag=%d)\n", send_count, send_tag);
        mpiPackedValue *src = shadowMPIPack(send_buf, send_count);
        mpiPackedValue *dst = shadowMPIAlloc(recv_count);
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        src,
                PIN_PARG(int),          send_count * sizeof(mpiPackedValue),
                PIN_PARG(MPI_Datatype), MPI_BYTE,
                PIN_PARG(int),          dest,
                PIN_PARG(int),          send_tag,
                PIN_PARG(void*),        dst,
                PIN_PARG(int),          recv_count * sizeof(mpiPackedValue),
                PIN_PARG(MPI_Datatype), MPI_BYTE,
                PIN_PARG(int),          source,
                PIN_PARG(int),          recv_tag,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG(MPI_Status*),  status,
                PIN_PARG_END());
        shadowMPIFree(src, send_count);
        shadowMPIUnpack(recv_buf, dst, recv_count);

    // otherwise, just call MPI_Send with original parameters
    } else {
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        send_buf,
                PIN_PARG(int),          send_count,
                PIN_PARG(MPI_Datatype), send_dt,
                PIN_PARG(int),          dest,
                PIN_PARG(int),          send_tag,
                PIN_PARG(void*),        recv_buf,
                PIN_PARG(int),          recv_count,
                PIN_PARG(MPI_Datatype), recv_dt,
                PIN_PARG(int),          dest,
                PIN_PARG(int),          recv_tag,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG(MPI_Status*),  status,
                PIN_PARG_END());
    }
    return rval;
}

int shadowMPIIsend(const CONTEXT *ctx, THREADID tid, AFUNPTR origFunPtr,
        void *buf, int count, MPI_Datatype dt, int dest, int tag, MPI_Comm comm, MPI_Request *rq)
{
    int rval;   // return value

    // if double precision, pack and send shadow values too
    if (dt == MPI_DOUBLE || dt == MPI_DOUBLE_PRECISION) {
        mpiPackedValue *tmp = shadowMPIPack(buf, count);
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        tmp,
                PIN_PARG(int),          count * sizeof(mpiPackedValue),
                PIN_PARG(MPI_Datatype), MPI_BYTE,
                PIN_PARG(int),          dest,
                PIN_PARG(int),          tag,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG(MPI_Request*), rq,
                PIN_PARG_END());
        //printf("Shadowed MPI_Isend (count=%d, dest=%d, tag=%d, rq=%ld)\n", count, dest, tag, (long)*rq);
        mpiNonBlockOp info;
        info.send = true;
        info.buf = buf;
        info.tmp = tmp;
        info.count = count;
        nonblockingOps[*rq] = info;

    // otherwise, just call MPI_Isend with original parameters
    } else {
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        buf,
                PIN_PARG(int),          count,
                PIN_PARG(MPI_Datatype), dt,
                PIN_PARG(int),          dest,
                PIN_PARG(int),          tag,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG(MPI_Request*), rq,
                PIN_PARG_END());
    }
    return rval;
}

int shadowMPIIrecv(const CONTEXT *ctx, THREADID tid, AFUNPTR origFunPtr,
        void *buf, int count, MPI_Datatype dt, int src, int tag, MPI_Comm comm, MPI_Request *rq)
{
    int rval;   // return value

    // if double precision, receive and unpack shadow data too
    if (dt == MPI_DOUBLE || dt == MPI_DOUBLE_PRECISION) {
        mpiPackedValue *tmp = shadowMPIAlloc(count);
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        tmp,
                PIN_PARG(int),          count * sizeof(mpiPackedValue),
                PIN_PARG(MPI_Datatype), MPI_BYTE,
                PIN_PARG(int),          src,
                PIN_PARG(int),          tag,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG(MPI_Request*), rq,
                PIN_PARG_END());
        //printf("Shadowed MPI_Irecv (count=%d, src=%d, tag=%d, rq=%ld)\n", count, src, tag, (long)*rq);
        mpiNonBlockOp info;
        info.send = false;
        info.buf = buf;
        info.tmp = tmp;
        info.count = count;
        nonblockingOps[*rq] = info;

    // otherwise, just call MPI_Irecv with original parameters
    } else {
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        buf,
                PIN_PARG(int),          count,
                PIN_PARG(MPI_Datatype), dt,
                PIN_PARG(int),          src,
                PIN_PARG(int),          tag,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG(MPI_Request*), rq,
                PIN_PARG_END());
    }
    return rval;
}

int shadowMPIWait(const CONTEXT *ctx, THREADID tid, AFUNPTR origFunPtr,
        MPI_Request *rq, MPI_Status *status)
{
    int rval;   // return value

    // save old request number ("rq" gets overwritten by wrapped call)
    MPI_Request oldRq = *rq;

    // call original
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
            PIN_PARG(int),          &rval,
            PIN_PARG(MPI_Request*), rq,
            PIN_PARG(MPI_Status*),  status,
            PIN_PARG_END());

    // if double precision, unpack shadow values too
    if (nonblockingOps.find(oldRq) != nonblockingOps.end()) {
        mpiNonBlockOp info = nonblockingOps[oldRq];
        //printf("Shadowing MPI_Wait (rq=%ld, count=%d)\n", (long)oldRq, info.count);
        if (info.send) {
            shadowMPIFree(info.tmp, info.count);
        } else {
            shadowMPIUnpack(info.buf, info.tmp, info.count);
        }
        nonblockingOps.erase(oldRq);
    }

    return rval;
}


int shadowMPIBcast(const CONTEXT *ctx, THREADID tid, AFUNPTR origFunPtr,
        void *buf, int count, MPI_Datatype dt, int root, MPI_Comm comm)
{
    int rval;   // original return value

    // if double precision, pack and broadcast shadow values too
    if (dt == MPI_DOUBLE || dt == MPI_DOUBLE_PRECISION) {
        //printf("Shadowing MPI_Bcast (count=%d, root=%d)\n", count, root);
        mpiPackedValue *tmp = shadowMPIPack(buf, count);
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        tmp,
                PIN_PARG(int),          count * sizeof(mpiPackedValue),
                PIN_PARG(MPI_Datatype), MPI_BYTE,
                PIN_PARG(int),          root,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());
        shadowMPIUnpack(buf, tmp, count);

    // otherwise, just call MPI_Bcast with original parameters
    } else {
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        buf,
                PIN_PARG(int),          count,
                PIN_PARG(MPI_Datatype), dt,
                PIN_PARG(int),          root,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());
    }
    return rval;
}

int shadowMPIScatter(const CONTEXT *ctx, THREADID tid, AFUNPTR origFunPtr,
        void *send_buf, int send_count, MPI_Datatype send_dt,
        void *recv_buf, int recv_count, MPI_Datatype recv_dt,
        int root, MPI_Comm comm)
{
    int rval;   // return value

    // if double precision, pack and gather shadow values too
    if (send_dt == MPI_DOUBLE || send_dt == MPI_DOUBLE_PRECISION) {
        int mpiRank, mpiSize;
        getMPICommRankSize(ctx, tid, comm, &mpiRank, &mpiSize);
        //printf("Shadowing MPI_Scatter (rank=%d, size=%d, send=%d, recv=%d)\n",
                //mpiRank, mpiSize, send_count, recv_count);

        // pack outgoing shadow values and allocate incoming array
        mpiPackedValue *src = NULL, *dst = shadowMPIAlloc(recv_count);
        if (mpiRank == root) {
            src = shadowMPIPack(send_buf, send_count * mpiSize);
        }

        // send out shadow values from root
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        src,
                PIN_PARG(int),          send_count * sizeof(mpiPackedValue),
                PIN_PARG(MPI_Datatype), MPI_BYTE,
                PIN_PARG(void*),        dst,
                PIN_PARG(int),          recv_count * sizeof(mpiPackedValue),
                PIN_PARG(MPI_Datatype), MPI_BYTE,
                PIN_PARG(int),          root,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());

        // unpack shadow values
        if (mpiRank == root) {
            shadowMPIFree(src, send_count * mpiSize);
        }
        shadowMPIUnpack(recv_buf, dst, recv_count);

    // otherwise, just call MPI_Scatter with original parameters
    } else {
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        send_buf,
                PIN_PARG(int),          send_count,
                PIN_PARG(MPI_Datatype), send_dt,
                PIN_PARG(void*),        recv_buf,
                PIN_PARG(int),          recv_count,
                PIN_PARG(MPI_Datatype), recv_dt,
                PIN_PARG(int),          root,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());
    }
    return rval;
}

int shadowMPIGather(const CONTEXT *ctx, THREADID tid, AFUNPTR origFunPtr,
        void *send_buf, int send_count, MPI_Datatype send_dt,
        void *recv_buf, int recv_count, MPI_Datatype recv_dt,
        int root, MPI_Comm comm)
{
    int rval;   // return value

    // if double precision, pack and gather shadow values too
    if (send_dt == MPI_DOUBLE || send_dt == MPI_DOUBLE_PRECISION) {
        int mpiRank, mpiSize;
        getMPICommRankSize(ctx, tid, comm, &mpiRank, &mpiSize);
        //printf("Shadowing MPI_Gather (rank=%d, size=%d, send=%d, recv=%d)\n",
                //mpiRank, mpiSize, send_count, recv_count);

        // pack outgoing shadow values and allocate incoming array
        mpiPackedValue *src, *dst = NULL;
        src = shadowMPIPack(send_buf, send_count);
        if (mpiRank == root) {
            dst = shadowMPIAlloc(recv_count * mpiSize);
        }

        // collect shadow values at root
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        src,
                PIN_PARG(int),          send_count * sizeof(mpiPackedValue),
                PIN_PARG(MPI_Datatype), MPI_BYTE,
                PIN_PARG(void*),        dst,
                PIN_PARG(int),          recv_count * sizeof(mpiPackedValue),
                PIN_PARG(MPI_Datatype), MPI_BYTE,
                PIN_PARG(int),          root,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());

        // unpack shadow values at root
        shadowMPIFree(src, send_count);
        if (mpiRank == root) {
            shadowMPIUnpack(recv_buf, dst, recv_count * mpiSize);
        }

    // otherwise, just call MPI_Gather with original parameters
    } else {
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        send_buf,
                PIN_PARG(int),          send_count,
                PIN_PARG(MPI_Datatype), send_dt,
                PIN_PARG(void*),        recv_buf,
                PIN_PARG(int),          recv_count,
                PIN_PARG(MPI_Datatype), recv_dt,
                PIN_PARG(int),          root,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());
    }
    return rval;
}

int shadowMPIAllgather(const CONTEXT *ctx, THREADID tid, AFUNPTR origFunPtr,
        void *send_buf, int send_count, MPI_Datatype send_dt,
        void *recv_buf, int recv_count, MPI_Datatype recv_dt, MPI_Comm comm)
{
    int rval;   // return value

    // if double precision, pack and gather shadow values too
    if (send_dt == MPI_DOUBLE || send_dt == MPI_DOUBLE_PRECISION) {
        int mpiRank, mpiSize;
        getMPICommRankSize(ctx, tid, comm, &mpiRank, &mpiSize);
        //printf("Shadowing MPI_Allgather (rank=%d, size=%d, send=%d, recv=%d)\n",
                //mpiRank, mpiSize, send_count, recv_count);

        // pack outgoing shadow values and allocate incoming array
        mpiPackedValue *src, *dst;
        src = shadowMPIPack(send_buf, send_count);
        dst = shadowMPIAlloc(recv_count * mpiSize);

        // collect shadow values too
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        src,
                PIN_PARG(int),          send_count * sizeof(mpiPackedValue),
                PIN_PARG(MPI_Datatype), MPI_BYTE,
                PIN_PARG(void*),        dst,
                PIN_PARG(int),          recv_count * sizeof(mpiPackedValue),
                PIN_PARG(MPI_Datatype), MPI_BYTE,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());

        // unpack shadow values
        shadowMPIFree(src, send_count);
        shadowMPIUnpack(recv_buf, dst, recv_count * mpiSize);

    // otherwise, just call MPI_Gather with original parameters
    } else {
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        send_buf,
                PIN_PARG(int),          send_count,
                PIN_PARG(MPI_Datatype), send_dt,
                PIN_PARG(void*),        recv_buf,
                PIN_PARG(int),          recv_count,
                PIN_PARG(MPI_Datatype), recv_dt,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());
    }
    return rval;
}

int shadowMPIAlltoall(const CONTEXT *ctx, THREADID tid, AFUNPTR origFunPtr,
        void *send_buf, int send_count, MPI_Datatype send_dt,
        void *recv_buf, int recv_count, MPI_Datatype recv_dt, MPI_Comm comm)
{
    int rval;   // return value

    // if double precision, pack and gather shadow values too
    if (send_dt == MPI_DOUBLE || send_dt == MPI_DOUBLE_PRECISION) {
        int mpiRank, mpiSize;
        getMPICommRankSize(ctx, tid, comm, &mpiRank, &mpiSize);
        //printf("Shadowing MPI_Alltoall (rank=%d, size=%d, send=%d, recv=%d)\n",
                //mpiRank, mpiSize, send_count, recv_count);

        // pack outgoing shadow values and allocate incoming array
        mpiPackedValue *src, *dst;
        src = shadowMPIPack(send_buf, send_count * mpiSize);
        dst = shadowMPIAlloc(recv_count * mpiSize);

        // collect shadow values too
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        src,
                PIN_PARG(int),          send_count * sizeof(mpiPackedValue),
                PIN_PARG(MPI_Datatype), MPI_BYTE,
                PIN_PARG(void*),        dst,
                PIN_PARG(int),          recv_count * sizeof(mpiPackedValue),
                PIN_PARG(MPI_Datatype), MPI_BYTE,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());

        // unpack shadow values
        shadowMPIFree(src, send_count * mpiSize);
        shadowMPIUnpack(recv_buf, dst, recv_count * mpiSize);

    // otherwise, just call MPI_Gather with original parameters
    } else {
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        send_buf,
                PIN_PARG(int),          send_count,
                PIN_PARG(MPI_Datatype), send_dt,
                PIN_PARG(void*),        recv_buf,
                PIN_PARG(int),          recv_count,
                PIN_PARG(MPI_Datatype), recv_dt,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());
    }
    return rval;
}



/******************************************************************************
 *                               MPI REDUCTIONS
 ******************************************************************************/

/*
 * pointers to MPI functions
 */
static AFUNPTR mpiOpCreatePtr;
static AFUNPTR mpiTypeContiguousPtr;

/*
 * MPI shadow operations
 */
static MPI_Op shadowMax  = 0;
static MPI_Op shadowMin  = 0;
static MPI_Op shadowSum  = 0;
static MPI_Op shadowProd = 0;

/*
 * MPI shadow data type
 */
static MPI_Datatype shadowType = 0;

/*
 * shadow reduction operations
 */
void shadowMPIOpMax(void *invec, void *inoutvec, int *len, MPI_Datatype *dt)
{
    mpiPackedValue *dest = (mpiPackedValue*)inoutvec;
    mpiPackedValue *src  = (mpiPackedValue*)invec;
    int count = (*len);
    for (int i = 0; i < count; i++) {
        dest->sys = (dest->sys < src->sys ? src->sys : dest->sys);
        SH_TYPE t1, t2;
        SH_ALLOC(t1); SH_ALLOC(t2);
        SH_UNPACK(t1, dest->shv);
        SH_UNPACK(t2, src->shv);
        SH_MAX(t1, t2);
        SH_PACK(dest->shv, t1);
        SH_FREE(t1); SH_FREE(t2);
        dest++;
        src++;
    }
}
void shadowMPIOpMin(void *invec, void *inoutvec, int *len, MPI_Datatype *dt)
{
    mpiPackedValue *dest = (mpiPackedValue*)inoutvec;
    mpiPackedValue *src  = (mpiPackedValue*)invec;
    int count = (*len);
    for (int i = 0; i < count; i++) {
        dest->sys = (dest->sys > src->sys ? src->sys : dest->sys);
        SH_TYPE t1, t2;
        SH_ALLOC(t1); SH_ALLOC(t2);
        SH_UNPACK(t1, dest->shv);
        SH_UNPACK(t2, src->shv);
        SH_MIN(t1, t2);
        SH_PACK(dest->shv, t1);
        SH_FREE(t1); SH_FREE(t2);
        dest++;
        src++;
    }
}
void shadowMPIOpSum(void *invec, void *inoutvec, int *len, MPI_Datatype *dt)
{
    mpiPackedValue *dest = (mpiPackedValue*)inoutvec;
    mpiPackedValue *src  = (mpiPackedValue*)invec;
    int count = (*len);
    for (int i = 0; i < count; i++) {
        dest->sys += src->sys;
        SH_TYPE t1, t2;
        SH_ALLOC(t1); SH_ALLOC(t2);
        SH_UNPACK(t1, dest->shv);
        SH_UNPACK(t2, src->shv);
        SH_ADD(t1, t2);
        SH_PACK(dest->shv, t1);
        SH_FREE(t1); SH_FREE(t2);
        //SH_SET(dest->shv, 0.0);       // for testing
        dest++;
        src++;
    }
}
void shadowMPIOpProd(void *invec, void *inoutvec, int *len, MPI_Datatype *dt)
{
    mpiPackedValue *dest = (mpiPackedValue*)inoutvec;
    mpiPackedValue *src  = (mpiPackedValue*)invec;
    int count = (*len);
    for (int i = 0; i < count; i++) {
        dest->sys *= src->sys;
        SH_TYPE t1, t2;
        SH_ALLOC(t1); SH_ALLOC(t2);
        SH_UNPACK(t1, dest->shv);
        SH_UNPACK(t2, src->shv);
        SH_MUL(t1, t2);
        SH_PACK(dest->shv, t1);
        SH_FREE(t1); SH_FREE(t2);
        dest++;
        src++;
    }
}

/*
 * call init on MPI user-defined shadow value type and operations
 */
inline void initializeMPIOps(const CONTEXT *ctx, THREADID tid)
{
    int rval;
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT,
            mpiTypeContiguousPtr, NULL,
            PIN_PARG(int),          &rval,
            PIN_PARG(int),          sizeof(mpiPackedValue),
            PIN_PARG(MPI_Datatype), MPI_BYTE,
            PIN_PARG(MPI_Datatype*),&shadowType,
            PIN_PARG_END());
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT,
            mpiOpCreatePtr, NULL,
            PIN_PARG(int),          &rval,
            PIN_PARG(void*),        &shadowMPIOpMax,
            PIN_PARG(int),          0,                  // commute = false
            PIN_PARG(MPI_Op*),      &shadowMax,
            PIN_PARG_END());
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT,
            mpiOpCreatePtr, NULL,
            PIN_PARG(int),          &rval,
            PIN_PARG(void*),        &shadowMPIOpMin,
            PIN_PARG(int),          0,                  // commute = false
            PIN_PARG(MPI_Op*),      &shadowMin,
            PIN_PARG_END());
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT,
            mpiOpCreatePtr, NULL,
            PIN_PARG(int),          &rval,
            PIN_PARG(void*),        &shadowMPIOpSum,
            PIN_PARG(int),          0,                  // commute = false
            PIN_PARG(MPI_Op*),      &shadowSum,
            PIN_PARG_END());
    PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT,
            mpiOpCreatePtr, NULL,
            PIN_PARG(int),          &rval,
            PIN_PARG(void*),        &shadowMPIOpProd,
            PIN_PARG(int),          0,                  // commute = false
            PIN_PARG(MPI_Op*),      &shadowProd,
            PIN_PARG_END());
    LOG("Registered custom MPI reduction type and operations.\n");
}

/*
 * translate between standard MPI reduction ops and shadow reduction ops
 */
inline MPI_Op getShadowMPIOp(MPI_Op op)
{
    MPI_Op rval = 0;
    switch (op) {
        case MPI_MAX:   rval = shadowMax;       break;
        case MPI_MIN:   rval = shadowMin;       break;
        case MPI_SUM:   rval = shadowSum;       break;
        case MPI_PROD:  rval = shadowProd;      break;
        default:        assert(!"Unsupported reduction operator");  break;
    }
    return rval;
}

/*
 * MPI wrappers
 */

int shadowMPIAllreduce(const CONTEXT *ctx, THREADID tid, AFUNPTR origFunPtr,
        void *send_buf, void *recv_buf, int count, MPI_Datatype dt, MPI_Op op, MPI_Comm comm)
{
    int rval;   // original return value

    // if double precision, reduce shadow values too
    if (dt == MPI_DOUBLE || dt == MPI_DOUBLE_PRECISION) {
        if (shadowSum == 0) {
            initializeMPIOps(ctx, tid);
        }

        //printf("Shadowing MPI_Allreduce (count=%d, op=%d)\n", count, op);

        // copy shadow values into (packed) temporary source array and
        // initialize temporary destination array
        mpiPackedValue *src  = shadowMPIPack(send_buf, count);
        mpiPackedValue *dest = shadowMPIAlloc(count);

        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        (void*)src,
                PIN_PARG(void*),        (void*)dest,
                PIN_PARG(int),          count,
                PIN_PARG(MPI_Datatype), shadowType,
                PIN_PARG(MPI_Op),       getShadowMPIOp(op),
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());

        shadowMPIFree(src, count);
        shadowMPIUnpack(recv_buf, dest, count);

    // otherwise, just call MPI_Allreduce with original parameters
    } else {
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        send_buf,
                PIN_PARG(void*),        recv_buf,
                PIN_PARG(int),          count,
                PIN_PARG(MPI_Datatype), dt,
                PIN_PARG(MPI_Op),       op,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());
    }
    return rval;
}

int shadowMPIReduce(const CONTEXT *ctx, THREADID tid, AFUNPTR origFunPtr,
        void *send_buf, void *recv_buf, int count, MPI_Datatype dt, MPI_Op op, int root, MPI_Comm comm)
{
    int rval;   // original return value

    // if double precision, reduce shadow values too
    if (dt == MPI_DOUBLE || dt == MPI_DOUBLE_PRECISION) {
        if (shadowSum == 0) {
            initializeMPIOps(ctx, tid);
        }

        int mpiRank, mpiSize;
        getMPICommRankSize(ctx, tid, comm, &mpiRank, &mpiSize);

        //printf("Shadowing MPI_Reduce (count=%d, op=%d, root=%d)\n", count, op, root);

        // copy shadow values into (packed) temporary source array and
        // initialize temporary destination array if we're the root
        mpiPackedValue *src  = shadowMPIPack(send_buf, count);
        mpiPackedValue *dest = NULL;
        if (mpiRank == root) {
            dest = shadowMPIAlloc(count);
        }

        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        (void*)src,
                PIN_PARG(void*),        (void*)dest,
                PIN_PARG(int),          count,
                PIN_PARG(MPI_Datatype), shadowType,
                PIN_PARG(MPI_Op),       getShadowMPIOp(op),
                PIN_PARG(int),          root,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());

        shadowMPIFree(src, count);
        if (mpiRank == root) {
            shadowMPIUnpack(recv_buf, dest, count);
        }

    // otherwise, just call MPI_Reduce with original parameters
    } else {
        PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_DEFAULT, origFunPtr, NULL,
                PIN_PARG(int),          &rval,
                PIN_PARG(void*),        send_buf,
                PIN_PARG(void*),        recv_buf,
                PIN_PARG(int),          count,
                PIN_PARG(MPI_Datatype), dt,
                PIN_PARG(MPI_Op),       op,
                PIN_PARG(MPI_Comm),     comm,
                PIN_PARG_END());
    }
    return rval;
}

#endif  // USE_MPI


/******************************************************************************
 *                        INSTRUMENTATION ROUTINES
 ******************************************************************************/

/*
 * total number of instructions instrumented (including duplicates)
 */
static unsigned long totalInstructions = 0;

/*
 * total number of instructions ignored (including duplicates)
 */
static UINT64 totalUnhandledInstructions = 0;

/*
 * save main executable image name for output file name
 */
VOID handleImage(IMG img, VOID *)
{
    if (IMG_IsMainExecutable(img)) {

        // save app name and PID
        appName = stripPath(IMG_Name(img).c_str());
        appPid = PIN_GetPid();

        // extract current host name
        char hn[MAX_HOSTNAME_LEN];
        if (!gethostname(hn, MAX_HOSTNAME_LEN)) {
            hostname = string(hn);
        }

        // determine output filename
        outFilename = KnobOutFile.Value().c_str();
        if (outFilename == string(DEFAULT_OUT_FN)) {
            outFilename = appName + "-shval-" + hostname +
                "-" + decstr(appPid) + ".log";
        }

        // open output file
        outFile.open(outFilename.c_str());
#if USE_MPI
    } else if (IMG_Name(img).find("libmpi") != string::npos) {
        mpiCommRankPtr = (AFUNPTR)RTN_Address(RTN_FindByName(img, "MPI_Comm_rank"));
        mpiCommSizePtr = (AFUNPTR)RTN_Address(RTN_FindByName(img, "MPI_Comm_size"));
        mpiOpCreatePtr = (AFUNPTR)RTN_Address(RTN_FindByName(img, "MPI_Op_create"));
        mpiTypeContiguousPtr = (AFUNPTR)RTN_Address(RTN_FindByName(img, "MPI_Type_contiguous"));
#endif
    }
}

/*
 * wrapper that instruments both the entry and exit of a memory allocation
 * function because Pin won't allow us to get both the parameters and the
 * return value in a single analysis routine
 */
void insertAllocCalls(RTN rtn, AFUNPTR entryFunc, AFUNPTR exitFunc, bool twoArgs)
{
    RTN_Open(rtn);
    if (twoArgs) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, entryFunc,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
    } else {
        RTN_InsertCall(rtn, IPOINT_BEFORE, entryFunc,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
    }
    RTN_InsertCall(rtn, IPOINT_AFTER, exitFunc,
            IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
}

/*
 * stubs for reporting functions
 */
VOID saveShadowValue(ADDRINT, ADDRINT);
VOID saveShadowArray(ADDRINT, ADDRINT, UINT64);
VOID saveError(ADDRINT, ADDRINT);
VOID saveErrorArray(ADDRINT, ADDRINT, UINT64);
VOID reportShadowValue(ADDRINT, ADDRINT);
VOID reportShadowArray(ADDRINT, ADDRINT, UINT64);
VOID clearShadowValue(ADDRINT);
VOID clearShadowArray(ADDRINT, UINT64);

/*
 * helper for inserting function-based calls
 */
void insertRtnCall(RTN rtn, IPOINT action, AFUNPTR func, int numArgs)
{
    RTN_Open(rtn);
    switch (numArgs) {
        case 0:
            RTN_InsertCall(rtn, action, func, IARG_END);
            break;
        case 1:
            RTN_InsertCall(rtn, action, func,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
            break;
        case 2:
            RTN_InsertCall(rtn, action, func,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_END);
            break;
        case 3:
            RTN_InsertCall(rtn, action, func,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_END);
            break;
        default:
            assert(!"Too many arguments!");
            break;
    }
    RTN_Close(rtn);
}

/*
 * helper for wrapping functions
 */
void replaceRtn(RTN rtn, AFUNPTR func, int numArgs)
{
    switch (numArgs) {
        case 2:
            RTN_ReplaceSignature(rtn, func,
                    IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_ORIG_FUNCPTR,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_END);
            break;
        case 5:
            RTN_ReplaceSignature(rtn, func,
                    IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_ORIG_FUNCPTR,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                    IARG_END);
            break;
        case 6:
            RTN_ReplaceSignature(rtn, func,
                    IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_ORIG_FUNCPTR,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                    IARG_END);
            break;
        case 7:
            RTN_ReplaceSignature(rtn, func,
                    IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_ORIG_FUNCPTR,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
                    IARG_END);
           break;
        case 8:
            RTN_ReplaceSignature(rtn, func,
                    IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_ORIG_FUNCPTR,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
                    IARG_END);
           break;
        case 12:
            RTN_ReplaceSignature(rtn, func,
                    IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_ORIG_FUNCPTR,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 8,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 11,
                    IARG_END);
           break;
        default:
            assert(!"Too many arguments!");
            break;
    }
}

/*
 * replace or wrap functions related to memory management, reporting, and MPI
 * communication
 */
VOID handleRoutine(RTN rtn, VOID *)
{
    string name = RTN_Name(rtn);
    //string libname = IMG_Name(SEC_Img(RTN_Sec(rtn)));
    //cout << "handling function \"" << name << "\" in " << libname << endl;

    if (name == "malloc" || name == "__libc_malloc") {
        insertAllocCalls(rtn, (AFUNPTR)SHVAL_malloc_entry,
                (AFUNPTR)SHVAL_malloc_exit, false);
    } else if (name == "calloc" || name == "__libc_calloc") {
        insertAllocCalls(rtn, (AFUNPTR)SHVAL_calloc_entry,
                (AFUNPTR)SHVAL_calloc_exit, true);
    } else if (name == "realloc" || name == "__libc_realloc") {
        insertAllocCalls(rtn, (AFUNPTR)SHVAL_realloc_entry,
                (AFUNPTR)SHVAL_realloc_exit, true);
    } else if (name == "free" || name == "__libc_free") {
        insertRtnCall(rtn, IPOINT_BEFORE, (AFUNPTR)SHVAL_free, 1);
    } else if (name == "SHVAL_saveShadowValue") {
        insertRtnCall(rtn, IPOINT_BEFORE, (AFUNPTR)saveShadowValue, 2);
    } else if (name == "SHVAL_saveShadowArray") {
        insertRtnCall(rtn, IPOINT_BEFORE, (AFUNPTR)saveShadowArray, 3);
    } else if (name == "SHVAL_saveError") {
        insertRtnCall(rtn, IPOINT_BEFORE, (AFUNPTR)saveError, 2);
    } else if (name == "SHVAL_saveErrorArray") {
        insertRtnCall(rtn, IPOINT_BEFORE, (AFUNPTR)saveErrorArray, 3);
    } else if (name == "SHVAL_reportShadowValue") {
        insertRtnCall(rtn, IPOINT_BEFORE, (AFUNPTR)reportShadowValue, 2);
    } else if (name == "SHVAL_reportShadowArray") {
        insertRtnCall(rtn, IPOINT_BEFORE, (AFUNPTR)reportShadowArray, 3);
    } else if (name == "SHVAL_clearShadowValue") {
        insertRtnCall(rtn, IPOINT_BEFORE, (AFUNPTR)clearShadowValue, 1);
    } else if (name == "SHVAL_clearShadowArray") {
        insertRtnCall(rtn, IPOINT_BEFORE, (AFUNPTR)clearShadowArray, 2);
    } else if (name == KnobReportFunction.Value()) {
        LOG("Reporting shadow values after function \"" + name + "\"\n");
        insertRtnCall(rtn, IPOINT_AFTER, (AFUNPTR)reportShadowValues, 0);
#if USE_MPI
    } else if (name == "MPI_Send"      || name == "PMPI_Send") {
        replaceRtn(rtn, (AFUNPTR)shadowMPISend, 6);
    } else if (name == "MPI_Recv"      || name == "PMPI_Recv") {
        replaceRtn(rtn, (AFUNPTR)shadowMPIRecv, 7);
    } else if (name == "MPI_Sendrecv"  || name == "PMPI_Sendrecv") {
        replaceRtn(rtn, (AFUNPTR)shadowMPISendrecv, 12);
    } else if (name == "MPI_Isend"     || name == "PMPI_Isend") {
        replaceRtn(rtn, (AFUNPTR)shadowMPIIsend, 7);
    } else if (name == "MPI_Irecv"     || name == "PMPI_Irecv") {
        replaceRtn(rtn, (AFUNPTR)shadowMPIIrecv, 7);
    } else if (name == "MPI_Wait"      || name == "PMPI_Wait") {
        replaceRtn(rtn, (AFUNPTR)shadowMPIWait, 2);
    } else if (name == "MPI_Bcast"     || name == "PMPI_Bcast") {
        replaceRtn(rtn, (AFUNPTR)shadowMPIBcast, 5);
    } else if (name == "MPI_Scatter"   || name == "PMPI_Scatter") {
        replaceRtn(rtn, (AFUNPTR)shadowMPIScatter, 8);
    } else if (name == "MPI_Gather"    || name == "PMPI_Gather") {
        replaceRtn(rtn, (AFUNPTR)shadowMPIGather, 8);
    } else if (name == "MPI_Allgather" || name == "PMPI_Allgather") {
        replaceRtn(rtn, (AFUNPTR)shadowMPIAllgather, 7);
    } else if (name == "MPI_Alltoall"  || name == "PMPI_Alltoall") {
        replaceRtn(rtn, (AFUNPTR)shadowMPIAlltoall, 7);
    } else if (name == "MPI_Allreduce" || name == "PMPI_Allreduce") {
        replaceRtn(rtn, (AFUNPTR)shadowMPIAllreduce, 6);
    } else if (name == "MPI_Reduce"    || name == "PMPI_Reduce") {
        replaceRtn(rtn, (AFUNPTR)shadowMPIReduce, 7);
#endif
    }
}

/*
 * extract and encode the idx-th XMM register read
 */
UINT32 encodeXMMRegR(INS ins, int idx)
{
    for (UINT32 i = 0; i < INS_MaxNumRRegs(ins); i++) {
        if (REG_is_xmm(INS_RegR(ins,i))) {
            if (idx == 0) {
                return INS_RegR(ins,i) - REG_XMM0;
            } else {
                idx--;
            }
        }
    }
    cerr << INS_Disassemble(ins) << endl;
    assert(!"no xmm register");
}

/*
 * extract and encode the idx-th XMM register written
 */
UINT32 encodeXMMRegW(INS ins, int idx)
{
    for (UINT32 i = 0; i < INS_MaxNumWRegs(ins); i++) {
        if (REG_is_xmm(INS_RegW(ins,i))) {
            if (idx == 0) {
                return INS_RegW(ins,i) - REG_XMM0;
            } else {
                idx--;
            }
        }
    }
    cerr << INS_Disassemble(ins) << endl;
    assert(!"no xmm register");
}

/*
 * These are generic instrumentation routines that build IARG parameters and
 * call Pin instrumentation functions directly; we try to front-load as much
 * computation as possible into the instrumentation routines to minimize the
 * amount of work done in the analysis routines.
 */

/*
 * move analysis generally requires data parameters, except for the xmm -> xmm
 * case
 */
VOID insertMovCall(INS ins, AFUNPTR readMemFunc, AFUNPTR writeMemFunc, AFUNPTR regFunc)
{
    if (INS_IsMemoryRead(ins) && readMemFunc != NULL) {
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowMem64IsInvalid,
                IARG_MEMORYREAD_EA, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
        INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowMem64Init,
                IARG_MEMORYREAD_EA, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)readMemFunc,
                IARG_MEMORYREAD_EA,
                IARG_UINT32, encodeXMMRegW(ins, 0),
                IARG_CALL_ORDER, CALL_ORDER_LAST,
                IARG_END);
        totalInstructions++;
    } else if (INS_IsMemoryWrite(ins) && writeMemFunc != NULL) {
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowMem64IsInvalid,
                IARG_MEMORYWRITE_EA, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
        INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowMem64InitEmpty,
                IARG_MEMORYWRITE_EA, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)writeMemFunc,
                IARG_UINT32, encodeXMMRegR(ins, 0),
                IARG_MEMORYWRITE_EA,
                IARG_CALL_ORDER, CALL_ORDER_LAST,
                IARG_END);
        totalInstructions++;
    } else if (INS_Opcode(ins) == XED_ICLASS_MOVQ && INS_OperandCount(ins) == 2 &&
            REG_is_xmm(INS_RegW(ins,0)) && !REG_is_xmm(INS_RegR(ins,0))) {
        // special case for movq gpr -> xmm
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowMovScalarGPR64ToReg64,
                IARG_REG_CONST_REFERENCE, INS_RegR(ins,0),
                IARG_UINT32, encodeXMMRegW(ins, 0),
                IARG_END);
        totalInstructions++;
    /* TODO: re-enable? (right now we're ignoring 32-bit movement)
     *} else if (INS_Opcode(ins) == XED_ICLASS_MOVD && INS_OperandCount(ins) == 2 &&
     *        REG_is_xmm(INS_RegW(ins,0)) && !REG_is_xmm(INS_RegR(ins,0))) {
     *    // special case for movd [gpr] -> [xmm]
     *    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowMovScalarGPR32ToReg32,
     *            IARG_REG_CONST_REFERENCE, INS_RegR(ins,0),
     *            IARG_UINT32, encodeXMMRegW(ins, 0),
     *            IARG_END);
     *    totalInstructions++;
     */
    } else if (INS_OperandCount(ins) == 2 &&
            !REG_is_xmm(INS_RegW(ins,0)) && REG_is_xmm(INS_RegR(ins,0))) {
        // ignore moves from XMM to GPRs
    } else if (regFunc != NULL && INS_OperandCount(ins) == 2 &&
            REG_is_xmm(INS_RegW(ins,0)) && REG_is_xmm(INS_RegR(ins,0))) {
        UINT32 sreg = encodeXMMRegR(ins, 0);
        UINT32 dreg = encodeXMMRegW(ins, 0);
        INS_InsertCall(ins, IPOINT_BEFORE,
                (AFUNPTR)regFunc,
                IARG_UINT32, sreg,
                IARG_UINT32, dreg,
                IARG_END);
        totalInstructions++;
    } else {
        LOG("WARNING - ignoring " + INS_Disassemble(ins)
                + " at " + hexstr(INS_Address(ins)) + "\n");
        totalUnhandledInstructions++;
    }
}

/*
 * basically the same as insertMovCall but without the special cases and with
 * specialized width handling
 */
VOID insertCvtCall(INS ins, AFUNPTR memReadFunc, AFUNPTR mem64ReadFunc, AFUNPTR regFunc, AFUNPTR reg64Func)
{
    if (INS_IsMemoryRead(ins) && INS_MemoryReadSize(ins) == 4 && memReadFunc != NULL) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)memReadFunc,
                IARG_MEMORYREAD_EA,
                IARG_UINT32, encodeXMMRegW(ins, 0), IARG_END);
        totalInstructions++;
    } else if (INS_IsMemoryRead(ins) && INS_MemoryReadSize(ins) == 8 && mem64ReadFunc != NULL) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mem64ReadFunc,
                IARG_MEMORYREAD_EA,
                IARG_UINT32, encodeXMMRegW(ins, 0), IARG_END);
        totalInstructions++;
    } else if (!INS_IsMemoryRead(ins) && !INS_IsMemoryWrite(ins) && INS_OperandWidth(ins, 1) == 32 && regFunc != NULL) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)regFunc,
                IARG_REG_CONST_REFERENCE, INS_RegR(ins, 0),
                IARG_UINT32, encodeXMMRegW(ins, 0), IARG_END);
        totalInstructions++;
    } else if (!INS_IsMemoryRead(ins) && !INS_IsMemoryWrite(ins) && INS_OperandWidth(ins, 1) == 64 && reg64Func != NULL) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)reg64Func,
                IARG_REG_CONST_REFERENCE, INS_RegR(ins, 0),
                IARG_UINT32, encodeXMMRegW(ins, 0), IARG_END);
        totalInstructions++;

    } else {
        LOG("WARNING - ignoring " + INS_Disassemble(ins) + "\n");
        totalUnhandledInstructions++;
    }
}

/*
 * insert instrumentation for binary operations
 */
VOID insertBinOpCall(INS ins, AFUNPTR memFunc, AFUNPTR regFunc)
{
    if (INS_IsMemoryRead(ins)) {
        if (memFunc != NULL) {
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowMem64IsInvalid,
                    IARG_MEMORYREAD_EA, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowMem64Init,
                    IARG_MEMORYREAD_EA, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)memFunc,
                    IARG_UINT32, encodeXMMRegW(ins,0),
                    IARG_MEMORYREAD_EA,
                    IARG_END);
            totalInstructions++;
        } else {
            LOG("WARNING - unhandled instruction: " + INS_Disassemble(ins)
                + " (" + hexstr(INS_Address(ins)) + ")\n");
            totalUnhandledInstructions++;
        }
    } else if (!INS_IsMemoryWrite(ins)) {
        if (regFunc != NULL) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)regFunc,
                    IARG_UINT32, encodeXMMRegR(ins,0),
                    IARG_UINT32, encodeXMMRegR(ins,1),
                    IARG_END);
            totalInstructions++;
        } else {
            LOG("WARNING - unhandled instruction: " + INS_Disassemble(ins)
                + " (" + hexstr(INS_Address(ins)) + ")\n");
            totalUnhandledInstructions++;
        }
    } else {
        // don't generally need to handle binary op memory writes b/c SSE does
        // not include any
        LOG("WARNING - unhandled instruction: " + INS_Disassemble(ins)
            + " (" + hexstr(INS_Address(ins)) + ")\n");
        totalUnhandledInstructions++;
    }
}

/*
 * insert instrumentation for unary operations
 */
VOID insertUnOpCall(INS ins, AFUNPTR memFunc, AFUNPTR regFunc)
{
    if (INS_IsMemoryRead(ins)) {
        if (memFunc != NULL) {
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowMem64IsInvalid,
                    IARG_MEMORYREAD_EA, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowMem64Init,
                    IARG_MEMORYREAD_EA, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)memFunc,
                    IARG_UINT32, encodeXMMRegW(ins,0),
                    IARG_MEMORYREAD_EA,
                    IARG_END);
            totalInstructions++;
        } else {
            LOG("WARNING - unhandled instruction: " + INS_Disassemble(ins)
                + " (" + hexstr(INS_Address(ins)) + ")\n");
            totalUnhandledInstructions++;
        }
    } else if (!INS_IsMemoryWrite(ins)) {
        if (regFunc != NULL) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)regFunc,
                    IARG_UINT32, encodeXMMRegW(ins,0),
                    IARG_UINT32, encodeXMMRegR(ins,0),
                    IARG_END);
            totalInstructions++;
        } else {
            LOG("WARNING - unhandled instruction: " + INS_Disassemble(ins)
                + " (" + hexstr(INS_Address(ins)) + ")\n");
            totalUnhandledInstructions++;
        }
    } else {
        // don't generally need to handle unary op memory writes b/c SSE does
        // not include any
        LOG("WARNING - unhandled instruction: " + INS_Disassemble(ins)
            + " (" + hexstr(INS_Address(ins)) + ")\n");
        totalUnhandledInstructions++;

    }
}

/*
 * insert instrumentation for bitwise operations
 */
VOID insertBitwiseOpCall(INS ins, AFUNPTR memFunc, AFUNPTR regFunc)
{
    if (INS_IsMemoryRead(ins)) {
        if (memFunc != NULL) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)memFunc,
                    IARG_INST_PTR,
                    IARG_UINT32, encodeXMMRegW(ins,0),
                    IARG_REG_CONST_REFERENCE, INS_RegW(ins,0),
                    IARG_MEMORYREAD_EA,
                    IARG_END);
            totalInstructions++;
        } else {
            LOG("WARNING - unhandled instruction: " + INS_Disassemble(ins)
                + " (" + hexstr(INS_Address(ins)) + ")\n");
            totalUnhandledInstructions++;
        }
    } else if (!INS_IsMemoryWrite(ins)) {
        if (regFunc != NULL) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)regFunc,
                    IARG_INST_PTR,
                    IARG_UINT32, encodeXMMRegR(ins,0),
                    IARG_UINT32, encodeXMMRegR(ins,1),
                    IARG_REG_CONST_REFERENCE, INS_RegR(ins,0),
                    IARG_REG_CONST_REFERENCE, INS_RegR(ins,1),
                    IARG_END);
            totalInstructions++;
        } else {
            LOG("WARNING - unhandled instruction: " + INS_Disassemble(ins)
                + " (" + hexstr(INS_Address(ins)) + ")\n");
            totalUnhandledInstructions++;
        }
    } else {
        // don't generally need to handle bitwise op memory writes b/c SSE does
        // not include any
        LOG("WARNING - unhandled instruction: " + INS_Disassemble(ins)
            + " (" + hexstr(INS_Address(ins)) + ")\n");
        totalUnhandledInstructions++;
    }
}

/*
 * is the instruction part of the SSE/AVX instruction set?
 */
bool isSSE(INS ins)
{
    // extract instruction info
    INT32 icategory = INS_Category(ins);
    INT32 iextension = INS_Extension(ins);

    // check for floating-point instructions
    return (
        icategory == XED_CATEGORY_SSE ||
        icategory == XED_CATEGORY_AVX ||
        icategory == XED_CATEGORY_AVX2 ||
        iextension == XED_EXTENSION_SSE ||
        iextension == XED_EXTENSION_SSE2 ||
        iextension == XED_EXTENSION_SSE3 ||
        iextension == XED_EXTENSION_SSE4 ||
        iextension == XED_EXTENSION_SSE4A ||
        iextension == XED_EXTENSION_SSSE3
    );
}

/*
 * insert calls to runtime/analysis update routines
 *
 * (this routine mostly just delegates to other routines to make the actual
 * instrumentation calls; it's basically a giant switch statement on the
 * instruction's opcode)
 */
VOID handleInstruction(INS ins, VOID *)
{
    bool skipCheck = false;

    // skip invalid routines (TODO: log these or re-enable?)
    RTN routine = INS_Rtn(ins);
    if (!RTN_Valid(routine)) {
        return;
    }

    // skip invalid images
    IMG image = SEC_Img(RTN_Sec(routine));
    if (!IMG_Valid(image)) {
        return;
    }

    // skip MPI and other low-level system libraries
    string libname = IMG_Name(image);
    if (libname.find("libmpich.so") != string::npos ||
        libname.find("ld-linux") != string::npos ||
        libname.find("libdl.so") != string::npos ||
        libname.find("librt.so") != string::npos ||
        libname.find("libnss") != string::npos ||
        libname.find("libpthread.so") != string::npos ||
        libname.find("libmunge.so") != string::npos ||
        libname.find("infinipath.so") != string::npos) {
        return;
    }

    // save instruction's disassembly and function name
    insDisas[INS_Address(ins)] = INS_Disassemble(ins);
    insFunc[INS_Address(ins)]  = RTN_Name(INS_Rtn(ins));

    // save instruction's address (if tracing is enabled)
    if (KnobOnlineTraceInsAddrs.Value()) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)setCurrentInsAddr,
                IARG_INST_PTR, IARG_END);
    }

    // check non-floating-point instructions for movement to/from a
    // floating-point memory location; otherwise, ignore non-SSE instructions
    if (!isSSE(ins)) {
        if (INS_IsMemoryWrite(ins)) {
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowMem64IsValid,
                    IARG_MEMORYWRITE_EA, IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowClearMem64,
                    IARG_MEMORYWRITE_EA, IARG_END);
            // unoptimized version
            // (re-enable if you want ENABLE_OVERWRITE_LOGGING here)
            //INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowMovToMem64,
                    //IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_END);
        }
        return;
    }

    // otherwise, what we do depends on the opcode
    //
    // (BEGIN GIANT SWITCH STATEMENT)
    //
    LEVEL_BASE::OPCODE iclass = INS_Opcode(ins);
    switch (iclass) {

    // simple data movement (ignore for now)
    /*
     *case XED_ICLASS_MOVSS:
     *    insertMovCall(ins, (AFUNPTR)shadowMovScalarMem32ToReg32,
     *                       (AFUNPTR)shadowMovScalarReg32ToMem32,
     *                       (AFUNPTR)shadowMovScalarReg32ToReg32); break;
     */
    case XED_ICLASS_MOVQ:
    case XED_ICLASS_MOVSD_XMM:
    case XED_ICLASS_MOVLPD:
        insertMovCall(ins, (AFUNPTR)shadowMovScalarMem64ToReg64,
                           (AFUNPTR)shadowMovScalarReg64ToMem64,
                           (AFUNPTR)shadowMovScalarReg64ToReg64); break;
    case XED_ICLASS_MOVAPD:
    case XED_ICLASS_MOVUPD:
    case XED_ICLASS_MOVNTPD:
    case XED_ICLASS_MOVNTDQ:
        insertMovCall(ins, (AFUNPTR)shadowMovPackedMem64ToReg64,
                           (AFUNPTR)shadowMovPackedReg64ToMem64,
                           (AFUNPTR)shadowMovPackedReg64ToReg64); break;
    case XED_ICLASS_MOVHPD:
        insertMovCall(ins, (AFUNPTR)shadowMovHighMem64ToReg64,
                           (AFUNPTR)shadowMovHighReg64ToMem64,
                           (AFUNPTR)shadowMovHighReg64ToReg64); break;

    // complex data movement
    case XED_ICLASS_UNPCKLPD:
    case XED_ICLASS_PUNPCKLQDQ:
        insertBinOpCall(ins, NULL, (AFUNPTR)shadowUNPCKLPD); break;
    case XED_ICLASS_UNPCKHPD:
    case XED_ICLASS_PUNPCKHQDQ:
        insertBinOpCall(ins, NULL, (AFUNPTR)shadowUNPCKHPD); break;
    case XED_ICLASS_UNPCKLPS:
        insertBinOpCall(ins, NULL, (AFUNPTR)shadowUNPCKLPS); break;
    case XED_ICLASS_UNPCKHPS:
        insertBinOpCall(ins, NULL, (AFUNPTR)shadowUNPCKHPS); break;
    case XED_ICLASS_MOVDDUP:
        insertUnOpCall (ins, NULL, (AFUNPTR)shadowMOVDDUP);  break;
    case XED_ICLASS_SHUFPD:
        if (!INS_IsMemoryRead(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowSHUFPD,
                    IARG_UINT32, encodeXMMRegW(ins,0),
                    IARG_UINT32, encodeXMMRegR(ins,0),
                    IARG_UINT32, (UINT32)INS_OperandImmediate(ins,2),
                    IARG_END);
        } else {
            LOG("WARNING - unhandled instruction: " + INS_Disassemble(ins)
                + " (" + hexstr(INS_Address(ins)) + ")\n");
            totalUnhandledInstructions++;
        }
        break;

    // binary arithmetic operations
    case XED_ICLASS_ADDSD: insertBinOpCall(ins, (AFUNPTR)shadowADDSD_Mem64, (AFUNPTR)shadowADDSD); break;
    case XED_ICLASS_SUBSD: insertBinOpCall(ins, (AFUNPTR)shadowSUBSD_Mem64, (AFUNPTR)shadowSUBSD); break;
    case XED_ICLASS_MULSD: insertBinOpCall(ins, (AFUNPTR)shadowMULSD_Mem64, (AFUNPTR)shadowMULSD); break;
    case XED_ICLASS_DIVSD: insertBinOpCall(ins, (AFUNPTR)shadowDIVSD_Mem64, (AFUNPTR)shadowDIVSD); break;
    case XED_ICLASS_MINSD: insertBinOpCall(ins, (AFUNPTR)shadowMINSD_Mem64, (AFUNPTR)shadowMINSD); break;
    case XED_ICLASS_MAXSD: insertBinOpCall(ins, (AFUNPTR)shadowMAXSD_Mem64, (AFUNPTR)shadowMAXSD); break;
    case XED_ICLASS_ADDPD: insertBinOpCall(ins, (AFUNPTR)shadowADDPD_Mem64, (AFUNPTR)shadowADDPD); break;
    case XED_ICLASS_SUBPD: insertBinOpCall(ins, (AFUNPTR)shadowSUBPD_Mem64, (AFUNPTR)shadowSUBPD); break;
    case XED_ICLASS_MULPD: insertBinOpCall(ins, (AFUNPTR)shadowMULPD_Mem64, (AFUNPTR)shadowMULPD); break;
    case XED_ICLASS_DIVPD: insertBinOpCall(ins, (AFUNPTR)shadowDIVPD_Mem64, (AFUNPTR)shadowDIVPD); break;
    case XED_ICLASS_MINPD: insertBinOpCall(ins, (AFUNPTR)shadowMINPD_Mem64, (AFUNPTR)shadowMINPD); break;
    case XED_ICLASS_MAXPD: insertBinOpCall(ins, (AFUNPTR)shadowMAXPD_Mem64, (AFUNPTR)shadowMAXPD); break;

    // unary arithmetic operations
    case XED_ICLASS_SQRTSD:  insertUnOpCall(ins, (AFUNPTR)shadowSQRTSD_Mem64, (AFUNPTR)shadowSQRTSD); break;
    case XED_ICLASS_ROUNDSD: insertUnOpCall(ins, (AFUNPTR)shadowRNDSD_Mem64,  (AFUNPTR)shadowRNDSD);  break;
    case XED_ICLASS_SQRTPD:  case XED_ICLASS_VSQRTPD:
        insertUnOpCall(ins, (AFUNPTR)shadowSQRTPD_Mem64, (AFUNPTR)shadowSQRTPD); break;
    case XED_ICLASS_ROUNDPD: case XED_ICLASS_VROUNDPD:
        insertUnOpCall(ins, (AFUNPTR)shadowRNDPD_Mem64,  (AFUNPTR)shadowRNDPD);  break;

    // Stupid Floating-Point Tricks (TM)
    case XED_ICLASS_ANDPD:
    case XED_ICLASS_PAND:  insertBitwiseOpCall(ins, (AFUNPTR)shadowANDPD_Mem64,  (AFUNPTR)shadowANDPD);  break;
    case XED_ICLASS_ANDNPD:
    case XED_ICLASS_PANDN: insertBitwiseOpCall(ins, (AFUNPTR)shadowANDNPD_Mem64, (AFUNPTR)shadowANDNPD); break;
    case XED_ICLASS_ORPD:
    case XED_ICLASS_POR:   insertBitwiseOpCall(ins, (AFUNPTR)shadowORPD_Mem64,   (AFUNPTR)shadowORPD);   break;
    case XED_ICLASS_XORPD:
    case XED_ICLASS_PXOR:  insertBitwiseOpCall(ins, (AFUNPTR)shadowXORPD_Mem64,  (AFUNPTR)shadowXORPD);  break;

    // conversions
    case XED_ICLASS_CVTSI2SD:
        insertCvtCall(ins, (AFUNPTR)shadowCVTSI2SD_Mem64, (AFUNPTR)shadowCVTSI642SD_Mem64,
                           (AFUNPTR)shadowCVTSI2SD,       (AFUNPTR)shadowCVTSI642SD);           break;
    case XED_ICLASS_CVTSS2SD:
        insertCvtCall(ins, (AFUNPTR)shadowCVTSS2SD_Mem64, NULL, (AFUNPTR)shadowCVTSS2SD, NULL); break;
    case XED_ICLASS_CVTPS2PD:
        insertCvtCall(ins, NULL, (AFUNPTR)shadowCVTPS2PD_Mem64, NULL, (AFUNPTR)shadowCVTPS2PD); break;
    case XED_ICLASS_CVTDQ2PD:
        insertCvtCall(ins, NULL, (AFUNPTR)shadowCVTDQ2PD_Mem64, NULL, (AFUNPTR)shadowCVTDQ2PD); break;

    // we can safely ignore these (they have no effect on shadow values)
    //
    case XED_ICLASS_COMISS:         // ordered compare scalar single
    case XED_ICLASS_COMISD:         // ordered compare scalar double
    case XED_ICLASS_UCOMISS:        // unordered compare scalar single
    case XED_ICLASS_UCOMISD:        // unordered compare scalar double
    case XED_ICLASS_PCMPEQB:        // compare packed 8-bit ints:  equal-to
    case XED_ICLASS_PCMPEQW:        // compare packed 16-bit ints: equal-to
    case XED_ICLASS_PCMPEQD:        // compare packed 32-bit ints: equal-to
    case XED_ICLASS_PCMPGTB:        // compare packed 8-bit ints:  greater-than
    case XED_ICLASS_PCMPGTW:        // compare packed 16-bit ints: greater-than
    case XED_ICLASS_PCMPGTD:        // compare packed 32-bit ints: greater-than
    case XED_ICLASS_VPCMPEQB:       // compare packed 8-bit ints:  equal-to
    case XED_ICLASS_VPCMPEQW:       // compare packed 16-bit ints: equal-to
    case XED_ICLASS_VPCMPEQD:       // compare packed 32-bit ints: equal-to
    case XED_ICLASS_VPCMPGTB:       // compare packed 8-bit ints:  greater-than
    case XED_ICLASS_VPCMPGTW:       // compare packed 16-bit ints: greater-than
    case XED_ICLASS_VPCMPGTD:       // compare packed 32-bit ints: greater-than
    case XED_ICLASS_PCMPESTRI:      // compare explicit-length strings
    case XED_ICLASS_PCMPISTRI:      // compare implicit-length strings
    case XED_ICLASS_STMXCSR:        // save MXCSR register state
    case XED_ICLASS_LDMXCSR:        // load MXCSR register state
    case XED_ICLASS_FXSAVE:         // save x87/MMX/SSE state
    case XED_ICLASS_FXRSTOR:        // load x87/MMX/SSE state
    case XED_ICLASS_PMOVMSKB:       // move byte mask
    case XED_ICLASS_VPMOVMSKB:      // move byte mask
    case XED_ICLASS_MOVMSKPS:       // move 128-bit mask (single precision)
    case XED_ICLASS_MOVMSKPD:       // move 128-bit mask (double precision)
    case XED_ICLASS_MASKMOVDQU:     // non-temporal mask store to memory
    case XED_ICLASS_PEXTRB:         // extract 8 bits
    case XED_ICLASS_PEXTRW:         // extract 16 bits
    case XED_ICLASS_PEXTRD:         // extract 32 bits
    case XED_ICLASS_PEXTRQ:         // extract 64 bits
    case XED_ICLASS_VPEXTRB:        // extract 8 bits
    case XED_ICLASS_VPEXTRW:        // extract 16 bits
    case XED_ICLASS_VPEXTRD:        // extract 32 bits
    case XED_ICLASS_VPEXTRQ:        // extract 64 bits
    case XED_ICLASS_CVTSS2SI:       // convert single to signed int
    case XED_ICLASS_CVTTSS2SI:      // convert single to signed int (truncated)
    case XED_ICLASS_CVTSD2SI:       // convert double to signed int
    case XED_ICLASS_CVTTSD2SI:      // convert double to signed int (truncated)
    case XED_ICLASS_LFENCE:         // serialize loads
    case XED_ICLASS_SFENCE:         // serialize stores
    case XED_ICLASS_MFENCE:         // serialize loads and stores
    case XED_ICLASS_PAUSE:          // improve spin-wait loops
    case XED_ICLASS_PREFETCHT0:     // prefetch data
    case XED_ICLASS_PREFETCHT1:     // prefetch data
    case XED_ICLASS_PREFETCHT2:     // prefetch data
    case XED_ICLASS_PREFETCHW:      // prefetch data
    case XED_ICLASS_PREFETCHNTA:    // prefetch data
    case XED_ICLASS_POPCNT:         // count number of 1 bits
        skipCheck = true;
        break;

    // integer and single-precision operations; we'll mostly ignore these for
    // now except that we do need to invalidate any shadow values that may be
    // affected and inform the user that we're ignoring instructions
    //
    case XED_ICLASS_MOVD:           // 32-bit movement
    case XED_ICLASS_MOVNTI:         // non-temporal 32-bit movement
    case XED_ICLASS_MOVSS:          // single precision movement
    case XED_ICLASS_ADDSS:          // single precision scalar addition
    case XED_ICLASS_SUBSS:          // single precision scalar subtraction
    case XED_ICLASS_MULSS:          // single precision scalar muliplication
    case XED_ICLASS_DIVSS:          // single precision scalar division
    case XED_ICLASS_SQRTSS:         // single precision scalar square root
    case XED_ICLASS_ROUNDSS:        // single precision scalar rounding
    case XED_ICLASS_MINSS:          // single precision scalar minimum
    case XED_ICLASS_MAXSS:          // single precision scalar maximum
    case XED_ICLASS_RCPSS:          // single precision scalar reciprocal
    case XED_ICLASS_CVTSI2SS:       // convert signed int to single precision
    case XED_ICLASS_CVTSD2SS:       // convert double precision to single precision
    case XED_ICLASS_CMPSD_XMM:      // compare scalar double

        // clear the outputs
        if (INS_IsMemoryWrite(ins)) {
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowMem64IsValid,
                    IARG_MEMORYWRITE_EA, IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowClearMem64,
                    IARG_MEMORYWRITE_EA, IARG_END);
            // unoptimized version
            // (re-enable if you want ENABLE_OVERWRITE_LOGGING here)
            //INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowMovToMem64,
                    //IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_END);
        } else if (REG_is_xmm(INS_RegW(ins, 0))) {
            INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)shadowResetReg64,
                    IARG_UINT32, encodeXMMRegW(ins, 0),
                    IARG_REG_CONST_REFERENCE, INS_RegW(ins, 0), IARG_END);
        }
        skipCheck = true;

        // log it
        LOG("WARNING - ignoring non-FP64 instruction: " + INS_Disassemble(ins)
            + " (" + hexstr(INS_Address(ins)) + ")\n");
        break;

    // packed integer and single-precision operations
    case XED_ICLASS_PADDB:          // add packed 8-bit integers
    case XED_ICLASS_PADDW:          // add packed 16-bit integers
    case XED_ICLASS_PADDD:          // add packed 32-bit integers
    case XED_ICLASS_PADDQ:          // add packed 64-bit integers
    case XED_ICLASS_PSUBB:          // subtract packed 8-bit integers
    case XED_ICLASS_PSUBW:          // subtract packed 16-bit integers
    case XED_ICLASS_PSUBD:          // subtract packed 32-bit integers
    case XED_ICLASS_PSUBQ:          // subtract packed 64-bit integers
    case XED_ICLASS_PMULUDQ:        // multiply unsigned packed 32-bit integers
    case XED_ICLASS_PMULLD:         // multiply signed packed 32-bit integers
    case XED_ICLASS_VPMULLD:        // multiply signed packed 32-bit integers
    case XED_ICLASS_PMULDQ:         // multiply signed packed 32-bit integers
    case XED_ICLASS_PSLLD:          // logical shift left packed 32-bit integers
    case XED_ICLASS_PSRLD:          // logical shift right packed 32-bit integers
    case XED_ICLASS_PSLLQ:          // logical shift left packed 64-bit integers
    case XED_ICLASS_PSRLQ:          // logical shift right packed 64-bit integers
    case XED_ICLASS_PSLLDQ:         // logical shift left packed 128-bit integers
    case XED_ICLASS_PSRLDQ:         // logical shift right packed 128-bit integers
    case XED_ICLASS_PSRAW:          // arithmetic shift right packed 16-bit integers
    case XED_ICLASS_PSRAD:          // arithmetic shift right packed 32-bit integers
    case XED_ICLASS_VPADDB:         // add packed 8-bit integers
    case XED_ICLASS_VPADDW:         // add packed 16-bit integers
    case XED_ICLASS_VPADDD:         // add packed 32-bit integers
    case XED_ICLASS_VPADDQ:         // add packed 64-bit integers
    case XED_ICLASS_VPSUBB:         // subtract packed 8-bit integers
    case XED_ICLASS_VPSUBW:         // subtract packed 16-bit integers
    case XED_ICLASS_VPSUBD:         // subtract packed 32-bit integers
    case XED_ICLASS_VPSUBQ:         // subtract packed 64-bit integers
    case XED_ICLASS_VPMULUDQ:       // multiply unsigned packed 32-bit integers
    case XED_ICLASS_VPSLLD:         // logical shift left packed 32-bit integers
    case XED_ICLASS_VPSRLD:         // logical shift right packed 32-bit integers
    case XED_ICLASS_VPSLLQ:         // logical shift left packed 64-bit integers
    case XED_ICLASS_VPSRLQ:         // logical shift right packed 64-bit integers
    case XED_ICLASS_VPSLLDQ:        // logical shift left packed 128-bit integers
    case XED_ICLASS_VPSRLDQ:        // logical shift right packed 128-bit integers
    case XED_ICLASS_VPSRAW:         // arithmetic shift right packed 16-bit integers
    case XED_ICLASS_VPSRAD:         // arithmetic shift right packed 32-bit integers
    case XED_ICLASS_PMINUB:         // minimum of packed unsigned 8-bit integers
    case XED_ICLASS_VPMINUB:        // minimum of packed unsigned 8-bit integers
    case XED_ICLASS_MOVDQA:         // move aligned 64-bit integers
    case XED_ICLASS_MOVDQU:         // move unaligned 64-bit integers
    case XED_ICLASS_LDDQU:          // move unaligned 128 bits
    case XED_ICLASS_PSHUFB:         // shuffle 8-bit integers
    case XED_ICLASS_PSHUFW:         // shuffle 16-bit integers
    case XED_ICLASS_PSHUFD:         // shuffle 32-bit integers (see above)
    case XED_ICLASS_VPSHUFB:        // shuffle 8-bit integers
    case XED_ICLASS_VPSHUFD:        // shuffle 32-bit integers (see above)
    case XED_ICLASS_PUNPCKLBW:      // interleave low 16-bit integers
    case XED_ICLASS_PUNPCKHBW:      // interleave high 16-bit integers
    case XED_ICLASS_PUNPCKLWD:      // interleave low 32-bit integers
    case XED_ICLASS_PUNPCKHWD:      // interleave high 32-bit integers
    case XED_ICLASS_PUNPCKLDQ:      // interleave low 64-bit integers
    case XED_ICLASS_PUNPCKHDQ:      // interleave high 64-bit integers
    case XED_ICLASS_MOVAPS:         // move aligned packed 32-bit floats
    case XED_ICLASS_MOVUPS:         // move unaligned packed 32-bit floats
    case XED_ICLASS_PINSRB:         // insert 8 bits
    case XED_ICLASS_PINSRW:         // insert 16 bits
    case XED_ICLASS_PINSRD:         // insert 32 bits
    case XED_ICLASS_PINSRQ:         // insert 64 bits
    case XED_ICLASS_VPINSRB:        // insert 8 bits
    case XED_ICLASS_VPINSRW:        // insert 16 bits
    case XED_ICLASS_VPINSRD:        // insert 32 bits
    case XED_ICLASS_VPINSRQ:        // insert 64 bits
    case XED_ICLASS_PALIGNR:        // align right
    case XED_ICLASS_VPALIGNR:       // align right
    case XED_ICLASS_ADDPS:          // single precision packed addition
    case XED_ICLASS_SUBPS:          // single precision packed subtraction
    case XED_ICLASS_MULPS:          // single precision packed muliplication
    case XED_ICLASS_DIVPS:          // single precision packed division
    case XED_ICLASS_SQRTPS:         // single precision packed square root
    case XED_ICLASS_ROUNDPS:        // single precision packed rounding
    case XED_ICLASS_MINPS:          // single precision packed minimum
    case XED_ICLASS_MAXPS:          // single precision packed maximum
    case XED_ICLASS_RCPPS:          // single precision packed reciprocal
    case XED_ICLASS_VRCPPS:         // single precision packed reciprocal
    case XED_ICLASS_ANDPS:          // single precision packed bitwise AND
    case XED_ICLASS_ANDNPS:         // single precision packed bitwise ANDN
    case XED_ICLASS_ORPS:           // single precision packed bitwise OR
    case XED_ICLASS_XORPS:          // single precision packed bitwise XOR
    case XED_ICLASS_SHUFPS:         // single precision shuffle
    case XED_ICLASS_VSHUFPS:        // single precision shuffle
    case XED_ICLASS_PCMPESTRM:      // compare explicit-length strings (save in XMM)
    case XED_ICLASS_PCMPISTRM:      // compare implicit-length strings (save in XMM)
    case XED_ICLASS_CMPPD:          // compare scalar double
    case XED_ICLASS_VCMPPD:         // compare scalar double
    case XED_ICLASS_CVTPS2DQ:       // convert packed singles to signed ints
    case XED_ICLASS_CVTTPS2DQ:      // convert packed singles to signed ints (truncated)
    case XED_ICLASS_CVTDQ2PS:       // convert signed ints to packed singles
    case XED_ICLASS_CVTPD2DQ:       // convert packed doubles to signed ints
    case XED_ICLASS_CVTTPD2DQ:      // convert packed doubles to signed ints (truncated)

    // TODO: properly implement support for these AVX instructions
    // (for now, just reset the shadow values for the destination)
    //
    case XED_ICLASS_VADDSD: case XED_ICLASS_VADDPD:
    case XED_ICLASS_VSUBSD: case XED_ICLASS_VSUBPD:
    case XED_ICLASS_VMULSD: case XED_ICLASS_VMULPD:
    case XED_ICLASS_VDIVSD: case XED_ICLASS_VDIVPD:
    case XED_ICLASS_VMINSD: case XED_ICLASS_VMINPD:
    case XED_ICLASS_VMAXSD: case XED_ICLASS_VMAXPD:
    case XED_ICLASS_VUNPCKLPD: case XED_ICLASS_VUNPCKHPD:
    case XED_ICLASS_VSHUFPD:
    case XED_ICLASS_VBLENDVPD:
    case XED_ICLASS_VZEROUPPER:

        // clear the outputs
        if (INS_IsMemoryWrite(ins)) {
            // TODO: optimize with if/then instrumentation?
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)shadowMovPackedToMem64,
                    IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_END);
        } else if (REG_is_xmm(INS_RegW(ins, 0))) {
            INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)shadowResetPackedReg64,
                    IARG_UINT32, encodeXMMRegW(ins, 0),
                    IARG_REG_CONST_REFERENCE, INS_RegW(ins, 0), IARG_END);
        }
        skipCheck = true;

        // log it
        LOG("WARNING - ignoring non-FP64 instruction: " + INS_Disassemble(ins)
            + " (" + hexstr(INS_Address(ins)) + ")\n");
        break;

    // flag anything we didn't know how to handle
    default:
        LOG("WARNING - unhandled instruction: " + INS_Disassemble(ins)
            + " (" + hexstr(INS_Address(ins)) + ")\n");
        totalUnhandledInstructions++;
        break;

    } // (END GIANT SWITCH STATEMENT)

    // do online shadow value validation after memory writes
    // (only for "exact" analyses run for validation; i.e., native64)
    //
    if ((KnobOnlineCheck.Value() || KnobOnlineCheckRegs.Value()) && !skipCheck) {
        if (INS_IsMemoryWrite(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)saveMemoryEA,
                    IARG_MEMORYWRITE_EA, IARG_END);
            INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)checkShadowValue,
                    IARG_ADDRINT, INS_Address(ins), IARG_END);
        } else if (KnobOnlineCheckRegs.Value() && REG_is_xmm(INS_RegW(ins, 0))) {
            INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)checkShadowReg,
                    IARG_UINT32, encodeXMMRegW(ins, 0),
                    IARG_REG_CONST_REFERENCE, INS_RegW(ins, 0),
                    IARG_ADDRINT, INS_Address(ins), IARG_END);
        }
    }
}


/******************************************************************************
 *                         MANAGEMENT AND REPORTING
 ******************************************************************************/

/*
 * used to ignore segfaults during reporting
 */
static sigjmp_buf skip_point;
void segfaultHandler(int code)
{
    siglongjmp(skip_point, SIGSEGV);
}

/*
 * final shadow value issue counts and stats
 */
static UINT64 finalShadowValueCount = 0;
static UINT64 finalErrorCount = 0;
static double finalAverageError = 0.0;
static double finalMaxError = 0.0;
static UINT64 finalSegfaultCount = 0;

/*
 * utility: print shadow values for SSE registers
 */
void dumpRegisterValues(ostream &out)
{
    out.precision(20);  // print floating-point values with 20 decimal places
    out << endl << "===  REGISTER SHADOW VALUES ===" << endl;
    out << "REG,SHADOW0,SHADOW1,SHADOW2,SHADOW3" << endl;
    for (int i = 0; i < 16; i++) {
        out << "xmm" << i << ",";
        SH_OUTPUT(out,xmm[XMM_SLOT(i,0)]); out << ",";
        SH_OUTPUT(out,xmm[XMM_SLOT(i,1)]); out << ",";
        SH_OUTPUT(out,xmm[XMM_SLOT(i,2)]); out << ",";
        SH_OUTPUT(out,xmm[XMM_SLOT(i,3)]); out << ",";
        out << endl;
    }
}

/*
 * print a value to the given output stream in CSV format
 */
void dumpMemValue(ostream &out, ADDRINT addr, double sys, const char *tag)
{
    out.precision(20);  // print floating-point values with 20 decimal places
    out << "0x" << std::hex << addr << std::dec
        << "," << sys
        << ",";
    SH_OUTPUT(out, SHMEM_ACCESS(addr));
    out.precision(4);   // print relative errors with 4 decimal places
    out << "," << SH_RELERR(SHMEM_ACCESS(addr), sys)
        << "," << tag
        << endl;
}

/*
 * user-requested shadow value extraction (single value)
 */
VOID saveShadowValue(ADDRINT loc, ADDRINT dest)
{
    *(double*)dest = SH_DBL(SHMEM_ACCESS(loc));
}

/*
 * user-requested shadow value extraction (multiple values)
 */
VOID saveShadowArray(ADDRINT loc, ADDRINT dest, UINT64 size)
{
    for (UINT32 i = 0; i < size; i++) {
        double *dloc = (double*)dest + i*sizeof(double);
        *dloc = SH_DBL(SHMEM_ACCESS(loc + i*sizeof(double)));
    }
}

/*
 * user-requested shadow error extraction (single value)
 */
VOID saveError(ADDRINT loc, ADDRINT dest)
{
    *(double*)dest = SH_RELERR(SHMEM_ACCESS(loc), *(double*)loc);
}

/*
 * user-requested shadow error extraction (multiple values)
 */
VOID saveErrorArray(ADDRINT loc, ADDRINT dest, UINT64 size)
{
    for (UINT32 i = 0; i < size; i++) {
        double *dloc = (double*)dest + i*sizeof(double);
        *dloc = SH_RELERR(SHMEM_ACCESS(loc + i*sizeof(double)),
                            *(double*)(loc + i*sizeof(double)));
    }
}

/*
 * user-requested shadow value reporting (single value)
 */
VOID reportShadowValue(ADDRINT loc, ADDRINT tag)
{
    double sys = *(double*)loc;
    if (KnobStdOutShadowDump.Value()) {
        dumpMemValue(cout, loc, sys, (char*)tag);
    } else {
        dumpMemValue(outFile, loc, sys, (char*)tag);
    }
}

/*
 * user-requested shadow value reporting (multiple values)
 */
VOID reportShadowArray(ADDRINT loc, ADDRINT tag, UINT64 size)
{
    for (UINT32 i = 0; i < size; i++) {
        ADDRINT iloc = loc + i*sizeof(double);
        double sys = *(double*)iloc;
        if (KnobStdOutShadowDump.Value()) {
            dumpMemValue(cout, iloc, sys, (char*)tag);
        } else {
            dumpMemValue(outFile, iloc, sys, (char*)tag);
        }
    }
}

/*
 * user-requested shadow value clearing (single value)
 */
VOID clearShadowValue(ADDRINT loc)
{
    shadowClearMem64(loc);
}

/*
 * user-requested shadow value clearing (multiple values)
 */
VOID clearShadowArray(ADDRINT loc, UINT64 size)
{
    for (UINT32 i = 0; i < size; i++) {
        ADDRINT iloc = loc + i*sizeof(double);
        shadowClearMem64(iloc);
    }
}

/*
 * utility: print active memory shadow values that have reportable errors
 * (or just dump all of them if requested)
 */
void dumpMemoryValues(ostream &out, bool dumpAll)
{
    outFile << "===  MEMORY SHADOW VALUES ===" << endl;
    outFile << "ADDR,SYSVAL,SHADOWVAL,RELERROR,TAG" << endl;

    ADDRINT addr;
    SHMEM_FOR_EACH(addr)

        // ignore stack locations (they're meaningless outside calling context)
        if (isStackAddr(addr)) {
            continue;
        }

        int code = sigsetjmp(skip_point, 1);
        if (code == 0) {

            signal(SIGSEGV, segfaultHandler);
            double sys = *(double*)addr;   // assumes original was 64 bits
            signal(SIGSEGV, SIG_DFL);

            bool isError = SH_ISERR(SHMEM_ACCESS(addr), sys);
            if (dumpAll || isError) {

                dumpMemValue(out, addr, sys, isError ? "ERROR" : "");

                if (isError) {
                    double relerr = SH_RELERR(SHMEM_ACCESS(addr), sys);
                    finalErrorCount++;
                    finalAverageError += relerr;
                    if (relerr > finalMaxError) {
                        finalMaxError = relerr;
                    }
                }
            }
            finalShadowValueCount++;

        } else {

            // re-enable to get the actual segfaulting locations
            // (disabled because there could be quite a few)
            //
            //LOG("WARNING - could not report shadow value for location "
                    //+ hexstr(addr) + " (segfault)\n");

            finalSegfaultCount++;
        }
    }

    // calculate average relative error
    if (finalErrorCount > 0) {
        finalAverageError /= (double)finalErrorCount;
    }
}

/*
 * debugger: add hooks that let us examine shadow values at runtime
 *
 * (run Pin with "-appdebug" option and attach from another window where you
 * have gdb running on the target executable--preferably with debug symbols
 * available)
 */
static BOOL handleDebug(THREADID, CONTEXT*,
        const string &cmd, string *result, VOID*)
{
    stringstream ss("");

    if (cmd == "dump") {            // dump all shadow values
        dumpMemoryValues(ss, true);

    } else if (cmd == "regs") {     // dump all register shadow values
        dumpRegisterValues(ss);

    } else if (cmd[0] == 'q') {     // query a specific address
        stringstream addrStr(cmd.substr(2));
        ADDRINT addr;
        addrStr >> std::hex >> addr;
        if (SHMEM_IS_VALID(addr)) {
            dumpMemValue(ss, addr, *(double*)addr, "");
        } else {
            ss << "No shadow value for 0x" << std::hex << addr << std::dec << endl;
        }
    }
    *result = ss.str();
    return !(*result == "");
}

/*
 * convert a memory size to a human-readable string (i.e., "3.5K")
 */
string humanReadableMemorySize(UINT64 bytes)
{
    double size = (double)bytes;
    if (size < 1024.0) { return fltstr(size,1) + "B"; } size /= 1024.0; // bytes
    if (size < 1024.0) { return fltstr(size,1) + "K"; } size /= 1024.0; // kilo
    if (size < 1024.0) { return fltstr(size,1) + "M"; } size /= 1024.0; // mega
    if (size < 1024.0) { return fltstr(size,1) + "G"; } size /= 1024.0; // giga
    if (size < 1024.0) { return fltstr(size,1) + "T"; } size /= 1024.0; // tera
    if (size < 1024.0) { return fltstr(size,1) + "P"; } size /= 1024.0; // peta
    return fltstr(size,1) + "E";    // exa    TODO: zetta/yotta? :)
}

/*
 * build statistical summary of shadow value analysis; some of this information
 * is calculated while the program is running but some of it is also calculated
 * in dumpMemoryValues(), so this function should be called after that one if
 * full information is desired
 */
string buildSummary()
{
    // build summary
    stringstream ss("");
    ss << "===  SHADOW VALUE SUMMARY  ===" << endl
       << "  Analyzed " << appName << " [pid=" << decstr(appPid) << "] running on " << hostname << endl
       << "  Elapsed time: " << ((double)(endTime.tv_sec - startTime.tv_sec) +
                                 (double)(endTime.tv_usec - startTime.tv_usec)/1000000000.0) << " seconds" << endl
       << "  Shadow value type: " << string(SH_INFO) << " (" << string(SH_PARAMS) << ")" << endl;
#if !USE_STL_MAP
    ss << "  Shadow value table max size: " << decstr(SHMEM_MAXSIZE) << " (mask=" << hexstr(SHMEM_MASK) << ")" << endl;
#endif
    ss << "  Instrumented " << totalInstructions << " instructions (possibly non-unique)" << endl;
    if (totalUnhandledInstructions > 0) {
       ss << "  Found " << totalUnhandledInstructions << " unhandled instructions (possibly non-unique)" << endl;
    }
    ss << "  Program allocated " << totalHeapBytes << " total bytes ("
       << humanReadableMemorySize(totalHeapBytes) << ") on the heap" << endl;
    ss << "  Program freed " << totalHeapBytesFreed << " total bytes ("
       << humanReadableMemorySize(totalHeapBytesFreed) << ") on the heap" << endl;
    if (KnobOnlineCheck.Value()) {
        ss << "  Detected " << totalRuntimeErrors << " total runtime mismatches" << endl;
    }
    ss << "  Checked " << finalShadowValueCount << " unique valid shadow values at end of \""
       << KnobReportFunction.Value()  + "\" function" << endl;
    ss << "  Detected " << finalErrorCount << " reportable errors" << endl;
    if (finalErrorCount > 0) {
        double tpct = (double)finalErrorCount / (double)finalShadowValueCount * 100.0;
        double hpct = (double)finalErrorCount / ((double)totalHeapBytes / 8.0) * 100.0;
        ss << "    Avg rel err = " << finalAverageError << "  Max rel err = " << finalMaxError << endl
           << "    " << fltstr(tpct,2) << "\% of checked values and "
           << fltstr(hpct,2) << "\% of total allocated heap space " << endl;
    }
    if (finalSegfaultCount > 0) {
        ss << "  Skipped " << finalSegfaultCount << " memory locations due to segfaults" << endl;
    }
    ss << "  Saved shadow value data to " << outFilename << endl
       << "===  END SHADOW VALUE SUMMARY  ===" << endl;
    return ss.str();
}

/*
 * termination: build and log summary, then de-allocate data structures
 */
VOID handleCleanup(INT32 code, VOID *v)
{
    // finalize timer
    gettimeofday(&endTime, NULL);

    // print and log a summary
    string summary = buildSummary();
    outFile << endl << summary;
    if (!KnobSkipSummary.Value()) {
        cout << summary;
    }
    LOG(summary);
    outFile.close();

    // clean up shadow value table
    SHMEM_FINI;

    // clean up shadow value data type
    SH_FINI;
}


/******************************************************************************
 *                             ENTRY POINT
 ******************************************************************************/

int main(int argc, char* argv[])
{
    // initialize Pin
    PIN_InitSymbols();  // we want symbol info if present
    if (PIN_Init(argc, argv)) {
        PIN_ERROR("This Pintool performs shadow value analysis on"
                  " floating-point arithmetic\n"
                + KNOB_BASE::StringKnobSummary() + "\n");
        return -1;
    }

    // initialize shadow value data type
    SH_INIT;

    // initialize XMM register shadow values
    for (UINT32 r = 0; r < 16; r++) {       // register id
        for (UINT32 t = 0; t < 4; t++) {    // tag
            SH_ALLOC(xmm[XMM_SLOT(r,t)]);
        }
    }

    // initialize memory shadow value table
    SHMEM_INIT;

    // use AT&T syntax (to match the GNU debugger)
    PIN_SetSyntaxATT();

    // register image instrumentation callback
    IMG_AddInstrumentFunction(handleImage, 0);

    // register routine instrumentation callback
    RTN_AddInstrumentFunction(handleRoutine, 0);

    // register instruction instrumentation callback
    INS_AddInstrumentFunction(handleInstruction, 0);

    // register debugging callback
    PIN_AddDebugInterpreter(handleDebug, 0);

    // register cleanup callback
    PIN_AddFiniFunction(handleCleanup, 0);

    // initialize timer
    gettimeofday(&startTime, NULL);

    // begin execution
    PIN_StartProgram();

    return 0;
}

