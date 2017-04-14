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
 * Floating-point dataflow trace analysis with dot graph output. This requires
 * Graphviz to convert to an actual image file. Example:
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

#define NODE(X,L)   fout << (X) << " [label=\"" << (L) << "\"];" << endl
#define EDGE(X,Y)   fout << (X) << " -> " << (Y) << endl

#define SH_TYPE         int
#define SH_INFO         "value trace"
#define SH_PARAMS       ""

#define SH_INIT         fout.open(KnobOutputFilename.Value().c_str()); \
                        fout << "digraph trace {" << endl
#define SH_ALLOC(V)     ;
#define SH_FREE(V)      ;
#define SH_SET(V,X)     NODE(nid,X); (V)=nid++
#define SH_COPY(V,S)    EDGE(S,nid); NODE(nid,"cpy"); (V)=nid++
#define SH_OUTPUT(O,V)  ;
#define SH_FINI         fout << "}" << endl; fout.close();

#define SH_PACKED_TYPE  int
#define SH_PACK(P,V)    (P)=(V)
#define SH_UNPACK(V,P)  (V)=(P)

#define SH_ADD(V,S)     EDGE(S,nid); EDGE(V,nid); NODE(nid,"+"); (V)=nid++
#define SH_SUB(V,S)     EDGE(S,nid); EDGE(V,nid); NODE(nid,"-"); (V)=nid++
#define SH_MUL(V,S)     EDGE(S,nid); EDGE(V,nid); NODE(nid,"*"); (V)=nid++
#define SH_DIV(V,S)     EDGE(S,nid); EDGE(V,nid); NODE(nid,"/"); (V)=nid++

#define SH_MIN(V,S)     EDGE(S,nid); EDGE(V,nid); NODE(nid,"min"); (V)=nid++
#define SH_MAX(V,S)     EDGE(S,nid); EDGE(V,nid); NODE(nid,"max"); (V)=nid++

#define SH_SQRT(V,S)    EDGE(S,nid); NODE(nid,"sqrt");  (V)=nid++
#define SH_ABS(V,S)     EDGE(S,nid); NODE(nid,"abs");   (V)=nid++
#define SH_NEG(V,S)     EDGE(S,nid); NODE(nid,"neg");   (V)=nid++
#define SH_RND(V,S)     EDGE(S,nid); NODE(nid,"round"); (V)=nid++

#define SH_DBL(V)       (0.0)
#define SH_RELERR(V,X)  (0.0)
#define SH_ISERR(V,X)   (false)

#include "shval.cpp"

