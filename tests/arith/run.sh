#!/bin/bash

make

INPUT="2 3 4"

rm -f *.log *.dot *.png *.svg *.txt

../../shval -n    -- ./main <<<"$INPUT"
../../shval -f    -- ./main <<<"$INPUT"
../../shval -d    -- ./main <<<"$INPUT"

../../shval -D    -- ./main <<<"$INPUT" && mv trace.dot diff.dot
../../shval -D -p -- ./main <<<"$INPUT" && mv trace.png diff.png
../../shval -D -s -- ./main <<<"$INPUT" && mv trace.svg diff.svg

../../shval -T    -- ./main <<<"$INPUT"
../../shval -T -p -- ./main <<<"$INPUT"
../../shval -T -s -- ./main <<<"$INPUT"
../../shval -T -t -- ./main <<<"$INPUT"

rm -f *.log

