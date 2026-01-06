#!/usr/bin/env bash


# pip installtion
#python3 -m pip install dnsgen

# go installtion
#go install github.com/d3mondev/puredns/v2@latest




shell=$(echo $SHELL | cut -d"/" -f4)
shell_path="$HOME/.${shell}rc"

if [[ "$EUID" -ne 0 ]]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

for file in ./scripts/*.sh; do
    
    [[ -e "$file" ]] || continue

    name="$(basename "${file%.sh}")"

    cp "$file" "/bin/$name"

done

echo "done."
