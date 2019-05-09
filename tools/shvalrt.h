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
 * Header for shadow value reporting hooks; to use these functions, include this
 * file while compiling and link against the corresponding static library.
 *
 * This should have minimal impact on your program unless you are running under
 * Pin with shadow value analysis, where calls to these functions will trigger
 * calls to actual functions in the SHVAL library.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void SHVAL_saveShadowValue(double *loc, double *dest);
void SHVAL_saveShadowArray(double *loc, double *dest, uint64_t size);

void SHVAL_saveError(double *loc, double *dest);
void SHVAL_saveErrorArray(double *loc, double *dest, uint64_t size);

void SHVAL_reportShadowValue(double *loc, const char *tag);
void SHVAL_reportShadowArray(double *loc, const char *tag, uint64_t size);

void SHVAL_clearShadowValue(double *loc);
void SHVAL_clearShadowArray(double *loc, uint64_t size);

#ifdef __cplusplus
}
#endif

