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
 * Shadow value analysis using the native 32-bit floating point data type
 */

#include <math.h>

#include "pin.H"

KNOB<double> KnobErrorThreshold(KNOB_MODE_WRITEONCE, "pintool",
        "err", "0.01", "relative error threshold for reporting (default=0.01)");

static double _relerr_threshold;

#define SH_TYPE         float
#define SH_INFO         "native 32-bit float"
#define SH_PARAMS       ("threshold=" + fltstr(_relerr_threshold,4))

#define SH_INIT         _relerr_threshold = KnobErrorThreshold.Value();
#define SH_ALLOC(V)     ;
#define SH_FREE(V)      ;
#define SH_SET(V,X)     (V)=(X)
#define SH_COPY(V,S)    (V)=(S)
#define SH_OUTPUT(O,V)  O << fltstr(V,6)

#define SH_ADD(V,S)     (V)=((V)+(S))
#define SH_SUB(V,S)     (V)=((V)-(S))
#define SH_MUL(V,S)     (V)=((V)*(S))
#define SH_DIV(V,S)     (V)=((V)/(S))
#define SH_MIN(V,S)     (V)=fminf((V),(S))
#define SH_MAX(V,S)     (V)=fmaxf((V),(S))
#define SH_SQRT(V,S)    (V)=sqrtf(S)
#define SH_ABS(V,S)     (V)=fabsf(S)
#define SH_NEG(V,S)     (V)=(-(S))
#define SH_RND(V,S)     (V)=roundf(S)

#define SH_DBL(V)       (double)(V)

// native32 only: assumes system value (X) is the "true" value for the purpose
// of relative error calculation (typically the shadow value is more precise and
// so it is used as the "true" value)
//
inline double _relerr(float v, double x)
{
    return ((x == 0.0) ? (v == 0.0f ? 0.0 : 1.0) : (fabs((double)x-v) / fabs(x)));
}

inline bool _iserr(float v, double x)
{
    bool vnan = isnan(v);
    bool xnan = isnan(x);
    return ( vnan && !xnan) ||
           (!vnan &&  xnan) ||
           (!vnan && !xnan && _relerr(v,x) > _relerr_threshold);
}

#define SH_RELERR(V,X)  (_relerr((V),(X)))
#define SH_ISERR(V,X)   (_iserr((V),(X)))

#include "shval.cpp"

