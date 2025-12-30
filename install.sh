#!/usr/bin/env bash

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
