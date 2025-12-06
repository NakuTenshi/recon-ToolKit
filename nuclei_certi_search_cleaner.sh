#!/bin/bash
sort -u $1 -o $1

while IFS= read -r line; do
    # echo $line
    raw=$(echo $line | cut -d" " -f5)
    array=($(echo "$raw" | jq -r '.[]'))

    # Print the array elements
    for i in "${array[@]}"; do
        echo "$i"
    done
    
done < $1
