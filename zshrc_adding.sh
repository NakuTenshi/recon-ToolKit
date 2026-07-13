setproxy() {
    export http_proxy="http://127.0.0.1:$1"
    export https_proxy="http://127.0.0.1:$1"
    export ftp_proxy="http://127.0.0.1:$1"
    export all_proxy="socks://127.0.0.1:$1/"

    export HTTP_PROXY="$http_proxy"
    export HTTPS_PROXY="$https_proxy"
    export FTP_PROXY="$ftp_proxy"
    export ALL_PROXY="$all_proxy"

    export no_proxy="localhost,127.0.0.0/8,::1"
    export NO_PROXY="$no_proxy"

    echo "[+] Proxy fully enabled"
}

# Disable proxy
unsetproxy() {
    unset http_proxy https_proxy ftp_proxy all_proxy
    unset HTTP_PROXY HTTPS_PROXY FTP_PROXY ALL_PROXY
    unset no_proxy NO_PROXY

    echo "[-] Proxy fully disabled"
}

myproxy() {
    echo "http proxy: $http_proxy"
    echo "https proxy: $https_proxy"
    echo "All proxy: $all_proxy"
}

myip () {
    curl -s http://ip-api.com/json | jq . 
}

export OPENROUTER_API_KEY="sk-or-your-key-here"
export ANTHROPIC_BASE_URL="https://openrouter.ai/api"
export ANTHROPIC_AUTH_TOKEN="$OPENROUTER_API_KEY"
export ANTHROPIC_API_KEY=""
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
export PDCP_API_KEY=bf2c155c-2034-431a-8f0b-72f0ead86a95


unalias gau
