#!/bin/bash

rm -f *.log *.dot *.svg *.txt

../../shval -T -s -- ./main

for i in $(seq 0 9); do
    dot2expr -i 0.$i trace.dot >expr-0.$i.txt
done

