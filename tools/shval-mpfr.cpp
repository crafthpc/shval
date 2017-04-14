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
 * Shadow value analysis using the GNU MPFR arbitrary precision data type with
 * the width set to 128 bits
 */

#include <cassert>
#include <cstddef>
#include <cstring>

#include <math.h>
#include <gmp.h>
#include <mpfr.h>

#include "pin.H"

KNOB<double> KnobErrorThreshold(KNOB_MODE_WRITEONCE, "pintool",
        "err", "0.01", "relative error threshold for reporting (default=0.01)");
KNOB<mpfr_prec_t> KnobNumBits(KNOB_MODE_WRITEONCE, "pintool",
        "bits", "128", "bits of precision (default=128)");

static double _relerr_threshold;
static mpfr_prec_t _bits;

#define MAX_PREC 256

#define BUF_SIZE 128
static char _buf[BUF_SIZE];

#define SH_TYPE         mpfr_t
#define SH_INFO         "GNU MPFR arbitrary-precision float"
#define SH_PARAMS       ("bits=" + decstr(_bits) + \
                         " threshold=" + fltstr(_relerr_threshold,4))

#define SH_INIT         _bits = KnobNumBits.Value(); \
                        assert(_bits < MAX_PREC); \
                        _relerr_threshold = KnobErrorThreshold.Value()
#define SH_ALLOC(V)     mpfr_init2((V),_bits)
#define SH_FREE(V)      mpfr_clear((V))
#define SH_SET(V,X)     mpfr_set_d((V),(X),GMP_RNDN)
#define SH_COPY(V,S)    mpfr_set((V),(S),GMP_RNDN)
#define SH_OUTPUT(O,V)  mpfr_snprintf(_buf,BUF_SIZE,"%.30Re",(V)); O << _buf

/*
 * "flattened" fixed-width data structure for MPI communication; basically, we
 * cap the number of "limbs" used for the arbitrary-precision significand
 */
typedef struct {
    mpfr_prec_t prec;
    mpfr_sign_t sign;
    mp_exp_t    exp;
    mp_limb_t   d[MAX_PREC];
} _packed_mpfr;

/*
 * convert an mpfr_t to the packed representation
 */
_packed_mpfr _pack(mpfr_t x)
{
    _packed_mpfr px;
    px.prec = x->_mpfr_prec;
    px.sign = x->_mpfr_sign;
    px.exp  = x->_mpfr_exp;
    assert((px.prec+1) < MAX_PREC);
    memcpy(px.d, x->_mpfr_d, mpfr_custom_get_size(px.prec));
    return px;
}

/*
 * convert the packed representation back to an mpfr_t
 */
void _unpack(mpfr_t x, _packed_mpfr px)
{
    mp_limb_t *limb = (mp_limb_t*)malloc(mpfr_custom_get_size(px.prec));
    memcpy(limb, px.d, mpfr_custom_get_size(px.prec));
    mpfr_clear(x);
    mpfr_custom_init_set(x, (mpfr_kind_t)(MPFR_REGULAR_KIND*px.sign),
            px.exp, px.prec, limb);
}

#define SH_PACKED_TYPE  _packed_mpfr
#define SH_PACK(P,V)    (P)=_pack(V)
#define SH_UNPACK(V,P)  _unpack(V,P)

#define SH_ADD(V,S)     mpfr_add((V),(V),(S),GMP_RNDN)
#define SH_SUB(V,S)     mpfr_sub((V),(V),(S),GMP_RNDN)
#define SH_MUL(V,S)     mpfr_mul((V),(V),(S),GMP_RNDN)
#define SH_DIV(V,S)     mpfr_div((V),(V),(S),GMP_RNDN)
#define SH_MIN(V,S)     mpfr_set((V),(mpfr_greater_p((V),(S)) ? (S) : (V)),GMP_RNDN)
#define SH_MAX(V,S)     mpfr_set((V),(mpfr_greater_p((V),(S)) ? (V) : (S)),GMP_RNDN)
#define SH_SQRT(V,S)    mpfr_sqrt((V),(S),GMP_RNDN)
#define SH_ABS(V,S)     mpfr_abs((V),(S),GMP_RNDN)
#define SH_NEG(V,S)     mpfr_neg((V),(S),GMP_RNDN)
#define SH_RND(V,S)     mpfr_set_d((V),round(mpfr_get_d((S),GMP_RNDN)),GMP_RNDN)

#define SH_DBL(V)       mpfr_get_d((V),GMP_RNDN)

inline double _relerr(mpfr_t v, double x)
{
    double shv = SH_DBL(v);

    // >64 bits: shadow value is more precise
    // <64 bits: system value is more precise
    double tru = (_bits > 64) ? shv : x;

    if (tru == 0.0) {
        return (shv == 0.0 ? 0.0 : 1.0);
    } else {
        return fabs(x - shv) / tru;
    }
}

inline bool _iserr(mpfr_t v, double x)
{
    bool vnan = mpfr_nan_p(v);
    bool xnan = isnan(x);
    return ( vnan && !xnan) ||
           (!vnan &&  xnan) ||
           (!vnan && !xnan && _relerr(v,x) > _relerr_threshold);
}

#define SH_RELERR(V,X)  (_relerr((V),(X)))
#define SH_ISERR(V,X)   (_iserr((V),(X)))

#include "shval.cpp"

