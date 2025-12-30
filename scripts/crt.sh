result=$(curl -s "https://crt.sh/?q=$1&output=json" | jq -r '.[] | .name_value, .common_name' | sort -u)

if [ -n "$2" ]; then
    echo "$result" > "$2"
else
    echo "$result"
fi

