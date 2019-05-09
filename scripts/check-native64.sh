#!/bin/bash
#
# Checks output of "native64 -c" runs for verification. Assumes analysis output
# is in folders named "native64-*" in the working directory.
#
# Copyright (c) 2017, Lawrence Livermore National Security, LLC.
# Produced at the Lawrence Livermore National Laboratory.
# Written by Michael O. Lam, lam26@llnl.gov. LLNL-CODE-729118.
# All rights reserved.
#
# This file is part of SHVAL. For details, see https://github.com/crafthpc/shval
#
# Please also see the LICENSE file for our notice and the LGPL.
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License (as published by the Free
# Software Foundation) version 2.1 dated February 1999.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the IMPLIED WARRANTY OF MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the terms and conditions of the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

grep "Segmentation fault" native64-*/*.out
grep "unhandled" native64-*/*.out
grep "runtime mismatches" native64-*/*.out
grep "ERROR" native64-*/*.out
grep "reportable errors" native64-*/*.out

