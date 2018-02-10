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

#include <stdio.h>
#include "shvalrt.h"

double iter(int n)
{
    double a = 1.0, b = 1.0, t;
    int i;
    for (i = 0; i < n; i++) {
        t = a + b;
        a = b;
        b = t;
        printf(" %f", b);
    }
    return a;
}

double rec(double n)
{
    if (n < 2.0) {
        return 1.0;
    }
    return rec(n-1.0) + rec(n-2.0);
}

int main()
{
    double i = iter(10);
    /*double r = rec(6.0);*/
    SHVAL_reportShadowValue(&i, "iter");
    /*SHVAL_reportShadowValue(&r, "rec");*/
    /*printf(" %f %f\n", i, r);*/
    return 0;
}

