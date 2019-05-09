#!/bin/bash

make

rm -f *.log *.dot *.svg

../../shval -Ts -- ./main

