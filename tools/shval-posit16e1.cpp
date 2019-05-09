/*
 * Copyright (c) 2017, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * Written by Michael O. Lam, lam26@llnl.gov. LLNL-CODE-729118.
 * All rights reserved.
 *
 * This file is part of SHVAL. For details, see https://github.com/crafthpc/shval
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
 * Shadow value analysis using John Gustafson's Posit representation,
 * with an implementation provided by Isaac Yonemoto:
 *
 * https://github.com/Etaphase/FastSigmoids.jl
 */

#include <cassert>

#include <math.h>

#include "pin.H"

#include "posit.h"
#include "posit_conv.h"
#include "posit_ops.h"

KNOB<double> KnobErrorThreshold(KNOB_MODE_WRITEONCE, "pintool",
        "err", "0.01", "relative error threshold for reporting (default=0.01)");

static double _relerr_threshold;

#define BUF_SIZE 4096
static char _buf[BUF_SIZE];

#define SH_TYPE         p16e1_t
#define SH_INFO         "Posit(16,1) number"
#define SH_PARAMS       ""

#define SH_INIT         ;
#define SH_ALLOC(V)     ;
#define SH_FREE(V)      ;
#define SH_SET(V,X)     (V) = f_to_p16e1(X)
#define SH_COPY(V,S)    (V) = (S)
#define SH_OUTPUT(O,V)  O << (float)p16e1_to_f(V)
#define SH_FINI         ;

#define SH_PACKED_TYPE  SH_TYPE
#define SH_PACK(P,V)    assert("Posits are not supported in MPI yet.")
#define SH_UNPACK(P,V)  assert("Posits are not supported in MPI yet.")

#define SH_ADD(V,S)     p16e1_add(&(V),(V),(S))
#define SH_SUB(V,S)     p16e1_sub(&(V),(V),(S))
#define SH_MUL(V,S)     p16e1_mul(&(V),(V),(S))
#define SH_DIV(V,S)     p16e1_div(&(V),(V),(S))
#define SH_MIN(V,S)     (V) = (p16e1_gt((V),(S)) ? (S) : (V))
#define SH_MAX(V,S)     (V) = (p16e1_gt((V),(S)) ? (V) : (S))
#define SH_SQRT(V,S)    p16e1_sqrt(&(V),(S))
#define SH_ABS(V,S)     assert("ABS function not supported yet.")
#define SH_NEG(V,S)     assert("NEG function not supported yet.")
#define SH_RND(V,S)     assert("RND function not supported yet.")

#define SH_DBL(V)       (double)(p16e1_to_f(V))

inline double _relerr(SH_TYPE v, double x)
{
    double shv = SH_DBL(v);

    // system value is more precise
    double tru = x;

    if (tru == 0.0) {
        return (shv == 0.0 ? 0.0 : 1.0);
    } else {
        return fabs(x - shv) / fabs(tru);
    }
}

inline bool _iserr(SH_TYPE v, double x)
{
    return ((x == 0.0) ? (SH_DBL(v) == 0.0f ? 0.0 : 1.0) : (fabs(x-SH_DBL(v)) / fabs(x)));
}

#define SH_RELERR(V,X)  (_relerr((V),(X)))
#define SH_ISERR(V,X)   (_iserr((V),(X)))

#include "shval.cpp"

