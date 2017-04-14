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
 * Shadow value analysis using the native 64-bit floating point data type
 */

#include <math.h>

#define SH_TYPE         double
#define SH_INFO         "native 64-bit double"
#define SH_PARAMS       ""

#define SH_INIT         ;
#define SH_ALLOC(V)     ;
#define SH_FREE(V)      ;
#define SH_SET(V,X)     (V)=(X)
#define SH_COPY(V,S)    (V)=(S)
#define SH_OUTPUT(O,V)  O << fltstr(V,15)

#define SH_ADD(V,S)     (V)=((V)+(S))
#define SH_SUB(V,S)     (V)=((V)-(S))
#define SH_MUL(V,S)     (V)=((V)*(S))
#define SH_DIV(V,S)     (V)=((V)/(S))
#define SH_MIN(V,S)     (V)=fmin((V),(S))
#define SH_MAX(V,S)     (V)=fmax((V),(S))
#define SH_SQRT(V,S)    (V)=sqrt(S)
#define SH_ABS(V,S)     (V)=fabs(S)
#define SH_NEG(V,S)     (V)=(-(S))
#define SH_RND(V,S)     (V)=round(S)

#define SH_DBL(V)       (V)

inline double _relerr(double v, double x)
{
    return ((x == 0.0) ? (v == 0.0 ? 0.0 : 1.0) : (fabs((double)x-v) / fabs(x)));
}

// native64 only: must match exactly or both be NaNs
//
inline bool _iserr(double v, double x)
{
    bool vnan = isnan(v);
    bool xnan = isnan(x);
    return ( vnan && !xnan) ||
           (!vnan &&  xnan) ||
           (!vnan && !xnan && v != x);
}

#define SH_RELERR(V,X)  (_relerr((V),(X)))
#define SH_ISERR(V,X)   (_iserr((V),(X)))

#include "shval.cpp"

