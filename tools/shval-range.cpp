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
 * Shadow value analysis using the native 64-bit floating point data type and
 * performing range tracking for output values.
 */

#include <cassert>
#include <cmath>
#include <limits>

static_assert(std::numeric_limits<double>::is_iec559, "IEEE 754 required");

typedef struct {
    double val;
    double min;
    double max;
} range_t;

#define CHECK(V)        (V).min = (((V).val < (V).min) ? (V).val : (V).min); \
                        (V).max = (((V).val > (V).max) ? (V).val : (V).max);

#define SH_TYPE         range_t
#define SH_INFO         "min/max range tracking"
#define SH_PARAMS       ""

#define SH_INIT         ;
#define SH_ALLOC(V)     (V).min = numeric_limits<double>::max(); \
                        (V).max = numeric_limits<double>::lowest()
#define SH_FREE(V)      ;
#define SH_SET(V,X)     (V).val = (X);     CHECK(V)
#define SH_COPY(V,S)    (V).val = (S).val; CHECK(V)
#define SH_OUTPUT(O,V)  O << "(" << fltstr((V).min,15) << "," << fltstr((V).max,15) << ")"
#define SH_FINI         ;

#define SH_PACKED_TYPE  range_t
#define SH_PACK(P,V)    (P)=(V)
#define SH_UNPACK(V,P)  (V)=(P)

#define SH_ADD(V,S)     (V).val=((V).val+(S).val);      CHECK(V)
#define SH_SUB(V,S)     (V).val=((V).val-(S).val);      CHECK(V)
#define SH_MUL(V,S)     (V).val=((V).val*(S).val);      CHECK(V)
#define SH_DIV(V,S)     (V).val=((V).val/(S).val);      CHECK(V)
#define SH_MIN(V,S)     (V).val=fmin((V).val,(S).val);  CHECK(V)
#define SH_MAX(V,S)     (V).val=fmax((V).val,(S).val);  CHECK(V)
#define SH_SQRT(V,S)    (V).val=sqrt((S).val);          CHECK(V)
#define SH_ABS(V,S)     (V).val=fabs((S).val);          CHECK(V)
#define SH_NEG(V,S)     (V).val=(-(S).val);             CHECK(V)
#define SH_RND(V,S)     (V).val=round((S).val);         CHECK(V)

#define SH_DBL(V)       (V).val

// range only: must lie inside range
// TODO: implement
//
inline bool _iserr(range_t v, double x)
{
    return false;
    //bool vnan = isnan(v);
    //bool xnan = isnan(x);
    //return ( vnan && !xnan) ||
           //(!vnan &&  xnan) ||
           //(!vnan && !xnan && (v != x);
}

#define SH_RELERR(V,X)  (0.0)
#define SH_ISERR(V,X)   _iserr((V),(X))

#include "shval.cpp"

