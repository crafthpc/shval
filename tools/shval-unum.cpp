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
 * Shadow value analysis using a Universal Number ("unum") library provided by
 * Scott LLoyd from LLNL: https://github.com/LLNL/unum
 *
 * Uses a (4,6) environment by default.
 */

#include <cassert>

#include <math.h>

#include "pin.H"

// unum library headers
//
#include "conv.h"
#include "hlayer.h"
#include "support.h"
#include "ubnd.h"
#include "uenv.h"
#include "ulayer.h"

KNOB<double> KnobErrorThreshold(KNOB_MODE_WRITEONCE, "pintool",
        "err", "0.01", "relative error threshold for reporting (default=0.01)");

static double _relerr_threshold;

// unum environment parameters
//
KNOB<UINT32> KnobUnumESS(KNOB_MODE_WRITEONCE, "pintool",
        "ess", "4", "unum exponent size size (ESS) (default=4)");
KNOB<UINT32> KnobUnumFSS(KNOB_MODE_WRITEONCE, "pintool",
        "fss", "6", "unum fraction size size (FSS) (default=6)");

static UINT32 _unum_ess;
static UINT32 _unum_fss;

#define BUF_SIZE 4096
static char _buf[BUF_SIZE];

#define SH_TYPE         ubnd_s
#define SH_INFO         "Universal number"
#define SH_PARAMS       (decstr(_unum_ess)+","+decstr(_unum_fss))

#define SH_INIT         _relerr_threshold = KnobErrorThreshold.Value(); \
                        _unum_ess = KnobUnumESS.Value(); \
                        _unum_fss = KnobUnumFSS.Value(); \
                        init_uenv(); set_uenv(_unum_ess, _unum_fss)
#define SH_ALLOC(V)     ubnd_init(&(V))
#define SH_FREE(V)      ubnd_clear(&(V))
#define SH_SET(V,X)     d2ub(&(V),(X))
#define SH_COPY(V,S)    ubnd_copy(&(V),&(S))
#define SH_OUTPUT(O,V)  sprint_ub(_buf,&(V)); O << _buf

#define SH_PACKED_TYPE  ubnd_s
#define SH_PACK(P,V)    assert("Unums are not supported in MPI yet.")
#define SH_UNPACK(P,V)  assert("Unums are not supported in MPI yet.")

#define SH_ADD(V,S)     plusu(&(V),&(V),&(S))
#define SH_SUB(V,S)     minusu(&(V),&(V),&(S))
#define SH_MUL(V,S)     timesu(&(V),&(V),&(S))
#define SH_DIV(V,S)     divideu(&(V),&(V),&(S))
#define SH_MIN(V,S)     ubnd_copy(&(V),(ub2d(&(V)) > ub2d(&(S)) ? &(S) : &(V)))
#define SH_MAX(V,S)     ubnd_copy(&(V),(ub2d(&(V)) > ub2d(&(S)) ? &(V) : &(S)))
#define SH_SQRT(V,S)    sqrtu(&(V),&(S))
#define SH_ABS(V,S)     absu(&(V),&(S))
#define SH_NEG(V,S)     negateu(&(V),&(S))
#define SH_RND(V,S)     d2ub(&(V),round(ub2d(&(S)))); (V).p=0

#define SH_DBL(V)       ub2d(&(V))

inline double _relerr(ubnd_s v, double x)
{
    double shv = SH_DBL(v);

    // >5 FSS: shadow value is more precise
    //   else: system value is (probably) more precise
    double tru = (_unum_fss > 5) ? shv : x;

    if (tru == 0.0) {
        return (shv == 0.0 ? 0.0 : 1.0);
    } else {
        return fabs(x - shv) / tru;
    }
}

inline bool _iserr(ubnd_s v, double x)
{
    UB_VAR(tmp);
    if (!v.p && exQ(v.l)) {
        // shadow value is exact; calculate relative error
        return (fabs((ub2d(&v)-x)/x) > _relerr_threshold);
    } else {
        // shadow value is a range; check containment
        return nequQ(d2ub(tmp, x), &v);
    }
}

#define SH_RELERR(V,X)  (_relerr((V),(X)))
#define SH_ISERR(V,X)   (_iserr((V),(X)))

#include "shval.cpp"

