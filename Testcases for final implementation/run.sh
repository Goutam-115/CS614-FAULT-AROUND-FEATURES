#!/bin/bash

# Check if the test1 program executable exists
if [ ! -f "./test1" ]; then
    echo "test1 program not found. Please compile your test1 program first."
    exit 1
fi

# CSV file header
echo "Memory Size (bytes),Time Oth (ms),Time 1st (ms),Time 2st(ms),Time 3rd(ms),Time 4th(ms),Time 5th(ms),Time 6th(ms),Time 7th (ms)" > new_recordings.csv

# Run the program multiple times
for i in {12..30}; do
    mem_size=$((1 << i))
    echo "Run : Memory access of $mem_size bytes"

    # Run the C program with the current memory size and capture the output
    echo 3 | sudo tee /proc/sys/vm/drop_caches
    output_prefault_1=$(./test1 1 $mem_size)
    echo 3 | sudo tee /proc/sys/vm/drop_caches
    output_prefault_2=$(./test1 2 $mem_size)
    echo 3 | sudo tee /proc/sys/vm/drop_caches
    output_prefault_3=$(./test1 3 $mem_size)
    echo 3 | sudo tee /proc/sys/vm/drop_caches
    output_prefault_4=$(./test1 4 $mem_size)
    echo 3 | sudo tee /proc/sys/vm/drop_caches
    output_prefault_5=$(./test1 5 $mem_size)
    echo 3 | sudo tee /proc/sys/vm/drop_caches
    output_prefault_6=$(./test1 6 $mem_size)
    echo 3 | sudo tee /proc/sys/vm/drop_caches
    output_prefault_7=$(./test1 7 $mem_size)
    echo 3 | sudo tee /proc/sys/vm/drop_caches
    output_no_prefault=$(./test1 0 $mem_size)
    #echo 3 | sudo tee /proc/sys/vm/drop_caches
    #output_map_populate=$(./test1 $mem_size 0)
    mem_size=$((mem_size >>10))
    # Reduction=$(echo "scale=2; 100*($output_no_prefault-$output_prefault)/$output_no_prefault" | bc)
    # Improvement=$(echo "scale=2; 100*($output_no_prefault-$output_prefault)/($output_no_prefault - $output_map_populate)" | bc)    # Append the memory size and times to the CSV file
    echo "$mem_size KB,$output_no_prefault,$output_prefault_1,$output_prefault_2,$output_prefault_3,$output_prefault_4,$output_prefault_5,$output_prefault_6,$output_prefault_7" >> new_recordings.csv
done

echo "Memory access test1s completed. Recorded in memory_access_recordings.csv"

