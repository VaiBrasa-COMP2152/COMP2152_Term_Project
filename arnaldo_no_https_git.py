# Author: Arnaldo Neto
# Vulnerability: Missing HTTPS Redirect on Git Server
# Target: git.0x10.cloud

import urllib.request
import time

# the git server im testing
url = "http://git.0x10.cloud"

print("checking HTTPS redirect on", url)
print("-" * 40)

try:
    # send http request and check if it stays on http or redirects to https
    response = urllib.request.urlopen(url, timeout=5)

    print("status code:", response.status)
    print("final url:", response.url)

    # if the final url is still http:// it means there is no redirect to https
    # this is the vulnerability
    if response.url.startswith("http://"):
        print("\nVULNERABILITY: No HTTPS redirect on git server!")
        print("git.0x10.cloud accepts plain HTTP with no redirect to HTTPS")
        print("credentials and source code travel in cleartext over the network")
        print("an attacker can intercept this traffic using a MITM attack")
    else:
        print("\nok, site redirects to HTTPS correctly")

    time.sleep(0.15)

except Exception as e:
    print("error:", e)

print("\n" + "-" * 40)
print("test complete.")
