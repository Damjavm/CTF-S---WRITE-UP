**Maquina: Casa Paco**

**Web: thehackerslabs.com**

![image](https://github.com/user-attachments/assets/22a0144e-407d-44f5-823e-af646661b9a2)

----------------------------------------------------------------------------------------------------------------------------------------------------

**Reconocimiento**

Nmap detecta los puertos 80/http y 22/ssh.

![image](https://github.com/user-attachments/assets/8ba784c2-08b2-4104-9fcc-5b47f42b4cbc)

Para acceder al sitio web agregamos el host a /etc/hosts.

![image](https://github.com/user-attachments/assets/782c60fe-3a43-4506-b1eb-5efd7cec5989)

![image](https://github.com/user-attachments/assets/b8ec6be6-ab52-4a5f-bf2c-22061c0c7488)

Haciendo un recorrido manual por el sitio web encontramos lo siguiente:

![Captura de pantalla 2025-01-19 123227](https://github.com/user-attachments/assets/3404b638-fb72-44c9-900d-63798f4e91b6)

Haciendo clic en el botón **Para Llevar** entramos a ```http://casapaco.thl/llevar.php```

![image](https://github.com/user-attachments/assets/748f3b7d-4559-498b-97d7-cba205b85066)

En esta entrada de texto probamos ejecutar comandos como ```id``` y nos devuelve información, con lo cual confirmamos la vulnerabilidad.

![image](https://github.com/user-attachments/assets/65d1f7c9-5147-4b94-a5b3-e610db0ba82f)

----------------------------------------------------------------------------------------------------------------------------------------------------

**Explotación**

Con Burpsuite interceptamos la petición y probamos ejecutar otros comandos para obtener más información.

![image](https://github.com/user-attachments/assets/a1ea4300-056f-4c2d-a942-8dfb04d323db)

Ahora que sabemos que hay otra pagina **Para Llevar** ```/llevar1.php``` intentamos ejecutar comandos allí para ver si nos devuelve más información que en la anterior pagina.

![image](https://github.com/user-attachments/assets/e5172e90-1ab0-493c-b73c-4c436b71cadd)

Con esto confirmamos que desde esta pagina podemos ejecutar comandos exitosamente. Ahora ejecutamos una reverse shell.

![image](https://github.com/user-attachments/assets/5c9a6d30-eb64-4118-89bf-7a40bbc65332)

Desde el directorio del usuario **pacogerente** se encuentra un script llamado ```fabada.sh``` el cual se está ejecutando, viendo los permisos, podemos aprovechar a modificarlo y otorgarnos acceso root para escalar privilegios.

![Captura de pantalla 2025-01-19 125551](https://github.com/user-attachments/assets/730d854a-4323-4787-8d98-aab831848db0)

![image](https://github.com/user-attachments/assets/aa1ca74f-1777-4060-83e6-f8d87a621218)

Somos root 🥳

Maquina completada 🏆
