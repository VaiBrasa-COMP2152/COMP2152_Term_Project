# Author: Arnaldo Neto
# Vulnerability: Missing X-Frame-Options Header (Clickjacking)
# Target: blog.0x10.cloud


import urllib.request
import time

# the site im testing
url = "https://blog.0x10.cloud"

print("checking security headers on", url)
print("-" * 40)

try:
    # open the url and get the response
    response = urllib.request.urlopen(url, timeout=5)
    headers = dict(response.headers)

    print("status code:", response.status)

    # i want to check if X-Frame-Options is there
    xframe = headers.get("X-Frame-Options")

    # also checking these ones just to see
    csp = headers.get("Content-Security-Policy")
    sts = headers.get("Strict-Transport-Security")

    print("\nheaders i found:")
    print("  X-Frame-Options:", xframe if xframe else "not found")
    print("  Content-Security-Policy:", csp if csp else "not found")
    print("  Strict-Transport-Security:", sts if sts else "not found")

    # if xframe is missing that means the site can be put inside an iframe
    # this is bad because attackers can trick users into clicking things
    # its called clickjacking
    if xframe is None:
        print("\nVULNERABILITY: X-Frame-Options header is missing!")
        print("this means the page can be loaded inside an iframe on another site")
        print("an attacker could use this to trick users into clicking stuff they didnt mean to")
    else:
        print("\nok the header is there, site looks fine")

    # small delay so i dont hit the rate limit
    time.sleep(0.15)

except Exception as e:
    # something went wrong
    print("error:", e)