#!/usr/bin/env python3

import sys
import requests
import base64
import random
import mmh3


userAgents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) "
    "Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) "
    "Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2_1) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
]

args = sys.argv
RED    = "\033[31m"
GREEN  = "\033[32m"
BLACK  = "\033[30m"
YELLOW = "\033[33m"
BLUE   = "\033[34m"
PURPLE = "\033[35m"
CYAN   = "\033[36m"
WHITE  = "\033[37m"
RESET = "\033[0m"

if len(args) > 1:
    urls = args[1:]
    for url in urls:
        if url.endswith(".png") or url.endswith(".ico") or url.endswith(".jpg") or url.endswith(".gif"):
            try:
                headers = {"User-Agent": random.choice(userAgents)}

                response = requests.get(url, headers=headers)
            except requests.exceptions.ConnectionError as e:
                print(f"{RED}[ERROR]{RESET} {url} got an Error while requesting")
                print(e)
                print("==============================================")
            else:
                if response.status_code == 200:
                    icon_content = response.content
                    icon_data = base64.encodebytes(icon_content)
                    hash = mmh3.hash(icon_data)

                    print(f"{GREEN}[*]{RESET} shodan quarys for {url}: ")
                    print(f"{GREEN}         https://www.shodan.io/search/report?query=http.favicon.hash:{hash}{RESET}")
                    print("")

                elif response.status_code == 404:
                    print(f"{RED}[ERROR]{RESET}favicon of {url} is not found")

        else:
            print(f"{RED}[ERROR]{RESET} invalid favicon format")
            print("format of favicon must be: .png, .ico, .jpg, .gif")

else:
    print(f"{RED}[ERROR]{RESET} no url proviced")
    scriptName = __file__.split("/")[-1]
    print(f"currect usage:\n\t{scriptName} http://site.com/favicon.ico")
    exit()