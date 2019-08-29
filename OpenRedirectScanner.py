#!/usr/bin/env python3
import sys
from colorama import Fore, Back, Style

print("Open Redirect Scanner")

#Check for common url redirect components
if len(sys.argv) < 2:
	print("Usage: python3 " + sys.argv[0] + " <file containing urls>")
	sys.exit()

url = sys.argv[1]
file = open(url, "r")
count = False
print("[*]Running scan for possible Open Redirect vulnerable URLs...\n")
for line in file:
	if "rl=" in line or "redirect=" in line or "next=" in line or "r=" in line or "u=" in line:
		print(Fore.GREEN + line)
		count = True
print(Style.RESET_ALL)
if count == False:
	print(Fore.RED + "[-]None found")
print(Style.RESET_ALL)
file.close()

# Check for 30* HTTP Status codes works best with dirbuster xml report
print("\n[*]These might require investigation to determine what causes the redirect")
count = False

file = open(url, "r")
for line in file:
	if 'responseCode="30' in line:
		print(Fore.GREEN + line)
		count = True
print(Style.RESET_ALL)
file.close()
if count == False:
	print(Fore.RED + "[-]None found. This only works if file contains HTTP Status codes\n")
print(Style.RESET_ALL)
print("Finished Scanning")

#Show examples of redirect bypass
print("\nTry the following https://www.example.com/?redirect_to=*")
print("""
https://attacker.com
target.com//attacker.com
target.com/@attacker.com
target.com/?image_url=attacker.com/.jpg
127.0.0.1
target.com/?redirect_url=target.com.attacker.com
https://attacker%E3%80%82com
target.com@%E2%80%AE@attacker.com
https:attacker.com
http:/\/\attacker.com
https:/\attacker.com.
.jp
""")
sys.exit()
