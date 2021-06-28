# NAT Sliptream samples
On October 31, 2020, @SamyKamkar published his [research on NAT Slipstreaming](https://medium.com/r/?url=https%3A%2F%2Fsamy.pl%2Fslipstream%2F). According to his own words, NAT Slipstreaming - 
… allows an attacker to remotely access any TCP/UDP service bound to a victim machine, bypassing the victim's NAT/firewall (arbitrary firewall pinhole control), just by the victim visiting a website.
I would go further and say that NAT Slipstreaming is actually more than that. I consider NAT Slipstreaming a whole vulnerability category. Basically, whenever an attacker can force a user to generate traffic to a specific server on the Internet and control both the content sent and the target port, you have a potential NAT Slipstreaming vulnerability.

The files present in this repository can be used for testing for NAT Slipstreaming vulnerabilities. The Google Chrome bug described at https://bugs.chromium.org/p/chromium/issues/detail?id=1184562 is an example of how the files present here can be used to exploit vulnerable browsers.

## punch.html
Sample malicious HTML page supporting different protocols.

## sip_s.py
Sample SIP malicious server.

## rtsp_s.py
Sample RTSP malicious server.

## h323_s.py
Sample h323 malicious server.