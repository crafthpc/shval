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
 * Null shadow value analysis (for performance testing)
 */

#define SH_TYPE         char
#define SH_INFO         "no shadow values"
#define SH_PARAMS       ""

#define SH_INIT         ;
#define SH_ALLOC(V)     ;
#define SH_FREE(V)      ;
#define SH_SET(V,X)     ;
#define SH_COPY(V,S)    ;
#define SH_OUTPUT(O,V)  ;

#define SH_ADD(V,S)     ;
#define SH_SUB(V,S)     ;
#define SH_MUL(V,S)     ;
#define SH_DIV(V,S)     ;
#define SH_MIN(V,S)     ;
#define SH_MAX(V,S)     ;
#define SH_SQRT(V,S)    ;
#define SH_ABS(V,S)     ;
#define SH_NEG(V,S)     ;
#define SH_RND(V,S)     ;

#define SH_DBL(V)       (0.0)
#define SH_RELERR(V,X)  (0.0)
#define SH_ISERR(V,X)   (false)

#include "shval.cpp"

