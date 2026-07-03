# orca

                  ,pW"Wq.  `7Mb,od8   ,p6"bo     ,6"Yb.  
                 6W'   `Wb   MM' "  '6M'  OO    8)   MM  
                 8M     M8   MM      8M          ,pm9MM  
                 YA.   ,A9   MM      YM.    ,   8M   MM  
                  `Ybmd9'  .JMML.     YMbmd'    `Moo9^Yo.

A Padding Oracle exploitation script in Python because I love PadBuster, but I always wanted to have my own version in Python.
## Features
 - Standard detection methods: HTTP status code, response length, keyword searches, location header
 - Advanced detection methods: HTTP/1.1 and HTTP/2 Time-based detection mechanisms for semi-blind padding oracles 
## Requirements
 - h2spacex - HTTP/2 low level library based on Scapy which can be used for Single Packet Attack (Race Condition on H2) https://github.com/nxenon/h2spacex
 - requests - HTTP for Humans™ https://requests.readthedocs.io/en/latest/
## Installation
```
pip install h2spacex
pip install requests
```
## Usage
```
usage: orca.py
REQUIRED ARGUMENTS:
url                   e.g. https://example.com:8081/page.aspx, http://example.com, https://127.0.0.1:8080
ciphertext            The ciphertext to attack - can be base64 encoded or a string of hex bytes. Provide a URL-decoded version. URL-encoding will be applied on output.
encoding              base64, None
method                GET, POST
blocksize             e.g. 8, 16, 32
body                  e.g. foo=bar&msg=

OPTIONAL ARGUMENTS:
--headers             {'Cookie': 'foo'} Note: Content-Type: application/x-www-form-urlencoded headers are added for POST method
--keyword             A custom, case-insensitive, keyword to search responses for 
--noiv                Activate 'no IV mode'
--lengthvariation     Make response length checking a fuzzy match
--protocol            HTTP1 / HTTP2 (time-based only)
--repeatruns          e.g. 1 / 2 / 4 / 8 (time-based only, HTTP/1 only)
--delayiftimebased    Add a delay to HTTP1 time-based attack (time-based only, HTTP/1 only)
--groupsize           e.g. 4 / 8 / 16 - Number of requests in each SPA (time-based only, HTTP/2 only)
```
