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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

#define MIN -1000000
#define MAX  1000000

typedef struct point {
    double x;
    double y;
} point_t;

double euclidean_distance(point_t a, point_t b);
double random_double(double min, double max);

int main()
{
    point_t a, b;
    double dist;

    srand(42);

    a.x = random_double(MIN, MAX);
    a.y = random_double(MIN, MAX);
    b.x = random_double(MIN, MAX);
    b.y = random_double(MIN, MAX);

    dist = euclidean_distance(a, b);

    printf("Euclidean Distance:\n\t(%f, %f)\n\t(%f, %f)\n", a.x, a.y, b.x, b.y);
    printf("\t%f\n", dist);

    return 0;
}

double euclidean_distance(point_t a, point_t b)
{
    return sqrt(pow(b.x - a.x, 2) + pow(b.y - a.y, 2));
}

double random_double(double min, double max)
{
    return min + (rand() / (RAND_MAX / (max - min)));
}
