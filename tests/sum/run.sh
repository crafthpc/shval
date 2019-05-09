#!/bin/bash

shval trace -- ./main
filter_dot trace.dot >filtered.dot

for i in $(seq 0 9); do
    dot2expr -i 0.$i filtered.dot >expr-0.$i.txt
done

