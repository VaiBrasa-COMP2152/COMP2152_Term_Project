# Author: Arnaldo 
# Vulnerability: Missing X-Frame-Options Header 
# Target: blog.0x10.cloud

import urllib.request
import time

TARGET = "https://blog.0x10.cloud"

print("=" * 55)
print("Testing: Missing X-Frame-Options Header")
print(f"Target: {TARGET}")
print("=" * 55)

try:
    # Send HTTP request to the target
    response = urllib.request.urlopen(TARGET, timeout=5)

    # Convert headers to dictionary
    headers = dict(response.headers)

    print(f"\nStatus: {response.status}")
    print(f"Final URL: {response.url}")

    # Display relevant security headers
    print("\n--- Security Headers Received ---")
    security_headers = [
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
    ]
    for h in security_headers:
        value = headers.get(h, "MISSING ⚠️")
        print(f"  {h}: {value}")

    # Check if X-Frame-Options is missing
    xframe = headers.get("X-Frame-Options", None)

    print("\n--- Result ---")
    if xframe is None:
        print("\n VULNERABILITY FOUND: Missing X-Frame-Options Header!")
        print("   The server does not return the X-Frame-Options header.")
        print("   This allows the page to be embedded inside an <iframe>")
        print("   on any malicious website.")
        print("   Risk: Clickjacking — an attacker can overlay the site")
        print("   with invisible layers, tricking users into clicking")
        print("   unintended actions (e.g. transfers, account changes).")
    else:
        print(f"\n X-Frame-Options present: {xframe}")
        print("   Site is protected against Clickjacking.")

except Exception as e:
    print(f"\n Connection error: {e}")

time.sleep(0.15)
print("\n" + "=" * 55)
print("Test complete.")
print("=" * 55)