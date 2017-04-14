#!/bin/bash
#
# Copyright (c) 2017, Lawrence Livermore National Security, LLC.
# Produced at the Lawrence Livermore National Laboratory.
# Written by Michael O. Lam, lam26@llnl.gov. LLNL-CODE-729118.
# All rights reserved.
#
# This file is part of SHVAL. For details, see https://github.com/lam2mo/shval
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

# should point to Pin installation
#PIN_ROOT="$HOME/opt/pin-3.0-76991-gcc-linux"
PIN_ROOT="$HOME/opt/pin-2.14-71313-gcc.4.4.7-linux"

# create output folder
mkdir -p obj-intel64

# debug mode
#PIN_ROOT=$PIN_ROOT DEBUG=1 make -j8 $@

# release mode
PIN_ROOT=$PIN_ROOT make -j8 $@

# build static runtime lib
gcc -g -fPIC -c shvalrt.c
ar rcs obj-intel64/shvalrt.a shvalrt.o
rm -f shvalrt.o

