#!/usr/bin/env python3
import sys


if len(sys.argv) < 2:
	print("Usage: python3 " + sys.argv[0] + " <file containing urls>")
	sys.exit()

url = sys.argv[1]
file = open(url, "r")

print("[*]Running scan for possible Open Redirect vulnerable URLs...")
for line in file:
	if "url=" in line or "redirect=" in line or "next=" in line or "r=" in line or "u=" in line:
		print(line)
file.close()
