#!/usr/bin/env python3 

import os
import requests
import json
import argparse
from bs4 import BeautifulSoup


parse = argparse.ArgumentParser("")
parse.add_argument('-d' , help="target's domain", required=True)

args = parse.parse_args()
domain = args.d

baseUrl = f"https://www.abuseipdb.com/whois/{domain}"
headers = {
    "User-Agent":'Mozilla/5.0 (X11; Linux x86_64; rv":"147.0) Gecko/20100101 Firefox/147.0',
    "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language":"en-US,en;q=0.9",
    "Accept-Encoding":"gzip, deflate, br",
    "Upgrade-Insecure-Requests":"1",
    "Sec-Fetch-Dest":"document",
    "Sec-Fetch-Mode":"navigate",
    "Sec-Fetch-Site":"none",
    "Sec-Fetch-User":"?1",
    "Priority":"u=0, i",
    "Te":"trailers"
}
cookies = {
    "cookie_consent_functional":"allow",
    "cookie_consent_analytical":"allow", 
    "_ga_MBHS9QPB71":"GS2.1.s1771303863$o3$g1$t1771303877$j46$l0$h0", 
    "_ga":"GA1.1.1960588983.1771238698", 
    "cf_clearance":"nWkr3eJh0WXXIyz.QWFIY_hmUB7oooN_Pspnxqs7DRM-1771305456-1.2.1.1-QSTiStNq0U8dio3TNG11hQulMokeRpHxi8xXlIVvcz_IZ7oI.nefWGIbLJ5g5JoaYH00z0gZhGnduNxIkeUpy27SQnu9kl.Jv7wrm984.gVC3UrWXpmp5VoF9zvYHjmzbybmg2dt_X_fJQV_ouNXwrU6llwrZgsZfnkIzasHVvvEUSllvwQKGp9wA6q9AtMKIj2NzPaLuWzSxV8959y.BJku6wU..Rcy4F7dD.2lfGk",
    "XSRF-TOKEN":"eyJpdiI6IlVIRUFuOUJjK2h2Rkg5R1FTS0ZrcEE9PSIsInZhbHVlIjoiNTduZ214U3F4alNRWmpvb3VhNXNEdUpVWUwybTJYZTNtUWl4R2lKVDRSMGR2OFhiK0ovRVlYYlptUjJWNkRFSkNsUEIwb0tCOTNlR2NRcUpVaTM4YktUOGlvYUlsMzdtZ0ZsaXlhelY1MVFzclBMVWZ1cnBMdVZNdDJISmoySW0iLCJtYWMiOiJlMzFjZDdlYWRlNzIxNzMxMTE5YzJlMjhmMmE3MjUwMTAyMGE5ZWRiY2U0YmE3ODM5M2Q5MTc4NDcwMjRjNjM4IiwidGFnIjoiIn0%3D",
    "abuseipdb_session":"eyJpdiI6IkdyeHBQR1NFQThvYmptUEN3ZHdVckE9PSIsInZhbHVlIjoiT0hwbDJvWHhYZnBzeTduQlkvUmw4NVFiNFlqZjF2dmhuY0ZkbWp2TjRKTFZldVJzT3lNZmorM3l6WEo4RlpHRkVPTFJtY1YyMFk4VWJSVGhvMnFRUVNBR3o1VFR1emJOQkwxZ3MralpUTUtSeVR6VFhIOTFsT0oyVDNLNEd3NUsiLCJtYWMiOiJlYTAzYjUwNDM1MTMyYmIwYWYzMjAxODJjNmFmYmQ5N2RmMmQ0Njk4NDAxOWQxN2E2YjJjNGExMzkyYjA0ZjJlIiwidGFnIjoiIn0%3D", 
    "env":"eyJpdiI6Ijc4TElBWTl6bnNjcThEN2hKQ3c5Wnc9PSIsInZhbHVlIjoiMDhiaWo4bmZhWEFMMGN0QURPM3V5WHlqeUpZaFByT3p4T0I2bHYvZ1MzaFJNcTlXQVNTeHFZakpsbHcvODhkcVRyK2xNcUhwOXV0MFFML0F4bmxoVUE9PSIsIm1hYyI6ImJmNDc5N2RlNGMxZGY3OTg3MmMzNThhZmE1OWQ3MDY0ZmVmMzMwYmRkNmNiNjMxMGM1YTIzZTM0MDExOGU2ZmMiLCJ0YWciOiIifQ%3D%3D"
}

response = requests.get(baseUrl, cookies=cookies, headers=headers)

if response.status_code == 200:
    soup = BeautifulSoup(response.content , "lxml")
    soup.find_all("div", class_="col-md-3")
    for div in soup.find_all("div", class_="col-md-3"):
        if len(div["class"]) == 1 and div["class"][0] == "col-md-3":
            subs = BeautifulSoup(str(div) , "lxml").find_all("li")
            for sub in subs:
                print(f"{sub.string}.{domain}")