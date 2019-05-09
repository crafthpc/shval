#!/bin/bash

for f in $(ls); do
    if [[ "$f" != "run_all.sh" ]]; then
        echo ""
        echo "== $f =="
        (cd $f && ./run.sh)
    fi
done

