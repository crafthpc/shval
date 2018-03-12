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
 * Floating-point dataflow differential trace analysis with dot graph output.
 * This requires Graphviz to convert to an actual image file. Example:
 *
 *      dot -Tpng -o trace.png trace.dot
 */

#include <iostream>
#include <fstream>

#include "pin.H"

KNOB<string> KnobOutputFilename(KNOB_MODE_WRITEONCE, "pintool",
        "of", "trace.dot", "output filename for dot graph (default=trace.dot)");

ofstream fout;
int nid = 0;

typedef struct {
    int id;
    float f32;
    double f64;
} diff_t;


#define NODE(V,L)   fout << (V)->id << " [label=\"" << (L) \
                         << " abserr=" << fabs(((V)->f64 - (V)->f32)) \
                         << " relerr=" << fabs(((V)->f64 - (V)->f32) / (V)->f64); \
                    if (KnobOnlineTraceInsAddrs.Value()) { \
                         fout << " addr=" << hex << getCurrentInsAddr() << dec \
                              << " disas='" << insDisas[getCurrentInsAddr()] \
                              << "' func='" << insFunc[getCurrentInsAddr()] \
                              << "' src=" << getSourceInfo(getCurrentInsAddr()); \
                    } \
                    fout << "\"];" << endl;
#define EDGE(X,Y)   fout << (X) << " -> " << (Y) << ";" << endl

#define SH_TYPE         diff_t*
#define SH_INFO         "differential trace"
#define SH_PARAMS       ""

#define SH_INIT         fout.open(KnobOutputFilename.Value().c_str()); \
                        fout << "digraph trace {" << endl
#define SH_ALLOC(V)     (V) = (diff_t*)malloc(sizeof(diff_t));
#define SH_FREE(V)      free(V);
#define SH_SET(V,X)     (V)->id  = nid++; \
                        (V)->f32 = (float)(X); \
                        (V)->f64 = (X); \
                        NODE(V,X);
#define SH_COPY(V,S)    (V)->id  = (S)->id; \
                        (V)->f32 = (S)->f32; \
                        (V)->f64 = (S)->f64;
#define SH_OUTPUT(O,V)  ;
#define SH_FINI         fout << "}" << endl; fout.close();

#define SH_PACKED_TYPE  diff_t
#define SH_PACK(P,V)    (P).id  = (V)->id; \
                        (P).f32 = (V)->f32; \
                        (P).f64 = (V)->f64;
#define SH_UNPACK(V,P)  (V)->id  = (P).id \
                        (V)->f32 = (P).f32; \
                        (V)->f64 = (P).f64;

#define SH_ADD(V,S)     EDGE((S)->id,nid); EDGE((V)->id,nid); \
                        (V)->id = nid++; (V)->f32 += (S)->f32; (V)->f64 += (S)->f64; \
                        NODE(V, "+")
#define SH_SUB(V,S)     EDGE((S)->id,nid); EDGE((V)->id,nid); \
                        (V)->id = nid++; (V)->f32 -= (S)->f32; (V)->f64 -= (S)->f64; \
                        NODE(V, "-")
#define SH_MUL(V,S)     EDGE((S)->id,nid); EDGE((V)->id,nid); \
                        (V)->id = nid++; (V)->f32 *= (S)->f32; (V)->f64 *= (S)->f64; \
                        NODE(V, "*")
#define SH_DIV(V,S)     EDGE((S)->id,nid); EDGE((V)->id,nid); \
                        (V)->id = nid++; (V)->f32 /= (S)->f32; (V)->f64 /= (S)->f64; \
                        NODE(V, "/")

#define SH_MIN(V,S)     EDGE((S)->id,nid); EDGE((V)->id,nid); \
                        if ((V)->f32 > (S)->f32) (V)->f32 = (S)->f32; \
                        if ((V)->f64 > (S)->f64) (V)->f64 = (S)->f64; \
                        (V)->id = nid++; NODE(V,"min");
#define SH_MAX(V,S)     EDGE((S)->id,nid); EDGE((V)->id,nid); \
                        if ((V)->f32 < (S)->f32) (V)->f32 = (S)->f32; \
                        if ((V)->f64 < (S)->f64) (V)->f64 = (S)->f64; \
                        (V)->id = nid++; NODE(V,"max");

#define SH_SQRT(V,S)    EDGE((S)->id,nid); (V)->id = nid++; \
                        (V)->f32 = sqrtf((S)->f32); (V)->f64 = sqrt((S)->f64); \
                        NODE(V,"sqrt");
#define SH_ABS(V,S)     EDGE((S)->id,nid); (V)->id = nid++; \
                        (V)->f32 = fabsf((S)->f32);  (V)->f64 = fabs((S)->f64); \
                        NODE(V,"abs");
#define SH_NEG(V,S)     EDGE((S)->id,nid); (V)->id = nid++; \
                        (V)->f32 = -((S)->f32); (V)->f64 = -((S)->f64); \
                        NODE(V,"neg");
#define SH_RND(V,S)     EDGE((S)->id,nid); (V)->id = nid++; \
                        (V)->f32 = roundf((S)->f32); (V)->f64 = round((S)->f64); \
                        NODE(V,"round");

#define SH_DBL(V)       ((V)->f64)
#define SH_RELERR(V,X)  (fabs(((V)->f64 - (X)) / ((V)->f64)))

// TODO: re-add threshold and do calculation
#define SH_ISERR(V,X)   (false)

#include "shval.cpp"

