#!/bin/bash

process_input() {
    while IFS= read -r line; do
        arr=($line)
        url="${arr[0]}"
        url="${url#http://}"
        url="${url#https://}"
        echo "$url"
    done
}

# Case 1: File argument provided
if [[ -n "$1" ]]; then
    if [[ -f "$1" ]]; then
        process_input < "$1"
    else
        echo "❌ File not found: $1" >&2
        exit 1
    fi

# Case 2: Data is piped via stdin
elif [[ ! -t 0 ]]; then
    process_input

# Case 3: Nothing provided
else
    echo "❌ No input provided."
    echo "Usage:"
    echo "  httpx_cleaner file.txt"
    echo "  cat file.txt | httpx_cleaner"
    exit 1
fi

