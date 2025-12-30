#!/usr/bin/env bash
set -u

process_input() {
    local line="$1"
    # remove common ANSI color sequences (if present)
    line=$(printf '%s' "$line" | sed -r 's/\x1B\[[0-9;]*[mK]//g')

    # extract the last [...] block (the JSON-like array at end of line)
    # this captures the first [...] group from the right (closest to line end)
    raw=$(printf '%s' "$line" | sed -n 's/.*\(\[[^]]*\]\).*/\1/p')

    # nothing to do if no bracketed array found
    [[ -z "$raw" ]] && return

    # quick jq validation; jq will return non-zero on invalid JSON
    if ! jq -e . >/dev/null 2>&1 <<<"$raw"; then
        # try to fix common issue: single quotes -> double quotes (if any)
        fixed=$(printf '%s' "$raw" | sed "s/'/\"/g")
        if jq -e . >/dev/null 2>&1 <<<"$fixed"; then
            raw="$fixed"
        else
            # give a helpful warning and skip
            printf 'warning: skipping invalid JSON array: %s\n' "$raw" >&2
            return
        fi
    fi

    # print each array element on its own line
    jq -r '.[]' <<<"$raw"
}

# ----- main -----
if [[ -n "${1-}" ]]; then
    if [[ -f "$1" ]]; then
        while IFS= read -r line; do
            process_input "$line"
        done < "$1"
    else
        echo "file not found: $1" >&2
        exit 1
    fi

elif [[ ! -t 0 ]]; then
    # read from stdin (pipe)
    while IFS= read -r line; do
        process_input "$line"
    done

else
    cat <<'USAGE' >&2
No input provided.
Usage:
  ./script.sh file.txt
  cat file.txt | ./script.sh
USAGE
    exit 1
fi
