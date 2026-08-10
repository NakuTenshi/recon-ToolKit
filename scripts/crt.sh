#!/bin/bash

# Usage: crt <domain> [output-file]

response=$(curl -s -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "https://crt.sh/?q=$1&output=json")
http_code="${response: -3}"                 # last 3 chars are status code
json_body="${response%???}"                 # everything before the status code

if [ "$http_code" -ne 200 ]; then
    exit 1
fi

# Check if the body is valid JSON (starts with '[' or '{')
if ! echo "$json_body" | jq empty 2>/dev/null; then
    exit 1
fi

result=$(echo "$json_body" | jq -r '.[] | .name_value, .common_name' | sort -u)

if [ -n "$2" ]; then
    echo "$result" > "$2"
else
    echo "$result"
fi
