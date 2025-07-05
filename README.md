# TRS Tarea 3: Inyección y Modificación de Tráfico en Protocolo IRC con Scapy

Este proyecto extiende el trabajo realizado en la Tarea 2, enfocándose en el análisis y manipulación del tráfico IRC utilizando **Scapy**. Se estudia el comportamiento del servidor y cliente IRC frente a la inyección o modificación de tráfico no esperado, con el objetivo de explorar vulnerabilidades o reacciones del sistema ante datos anómalos.

---

## Tabla de contenido

- [Información general](#información-general)
- [Tecnologías utilizadas](#tecnologías-utilizadas)
- [Instalación del entorno desde cero](#instalación-del-entorno-desde-cero)
- [Uso de Scapy para inyección y modificación](#uso-de-scapy-para-inyección-y-modificación)
- [Autores](#autores)

---

## Información general

El objetivo de esta tarea es interceptar, inyectar y modificar tráfico IRC entre un cliente y un servidor, utilizando herramientas como **Scapy**. A través de estas modificaciones, se pretende observar y documentar los efectos sobre el comportamiento del servicio.

---

## Tecnologías utilizadas

- Docker
- InspIRCd (Servidor IRC)
- Irssi (Cliente IRC)
- Scapy (Python 3)
- Terminal bash
- Sistema operativo Linux

---

## Instalación del entorno desde cero

### 1. Instalar Python y pip

```bash
sudo apt update
sudo apt install -y python3 python3-pip
```

Verificar instalación:

```bash
python3 --version
pip3 --version
```

### 2. Instalar Scapy y herramientas de red

```bash
pip3 install scapy
sudo apt install -y net-tools tcpdump tshark
```

### 3. Instalar servidor IRC (Docker)

```bash
docker run -d --name irc-server -p 6667:6667 inspircd/inspircd-docker
```

### 4. Instalar cliente IRC (Docker)

```bash
docker run -it --name irc-client --network host irssi
```

---

## Uso de Scapy para inyección y modificación


Una inyección de tráfico tiene como objetivo evaluar la robustez del protocolo ante entradas malformadas, simulando un comportamiento anómalo o malicioso. Se realizaron dos pruebas de fuzzing.

## Fuzzing 1: Mensaje `PRIVMSG` largo

El objetivo de esta prueba es evaluar la robustez del servidor IRC frente a mensajes `PRIVMSG` con longitudes excesivas y caracteres inusuales, simulando una entrada anómala que podría surgir por errores de programación o ataques maliciosos. Se busca observar cómo el servidor maneja este tipo de mensajes: si los rechaza, cierra la conexión, o simplemente los ignora.

Se espera que el servidor pueda:

- Rechazar el mensaje por violar alguna política de formato o longitud.
- Cerrar la conexión por motivos de seguridad.
- Ignorar el contenido sin generar respuesta alguna.

Se diseñó un script en Python utilizando la biblioteca Scapy para construir y enviar un paquete TCP/IP con una carga útil `PRIVMSG` de 300 caracteres aleatorios. El script se ejecutó en un entorno de red local donde el servidor IRC se encuentra en la dirección IP `172.17.0.2`, puerto `6667`. A continuación se presenta el código utilizado:

```python
from scapy.all import *
import random, string

msg = "PRIVMSG #canal :" + ''.join(random.choices(string.printable, k=300)) + "\r\n"
pkt = IP(dst="172.17.0.2") / TCP(dport=6667, sport=RandShort(), flags="PA") / Raw(load=msg.encode())
send(pkt)
```

### Observación

Al ejecutar el script y capturar el tráfico con Wireshark utilizando el filtro `tcp.port == 6667`, se observó el siguiente comportamiento:

- **Primer paquete TCP:** Se visualiza correctamente un paquete con carga útil que contiene el comando `PRIVMSG` seguido de 300 caracteres aleatorios.
- **Segundo paquete TCP (en rojo):** Wireshark lo marca como un paquete anómalo, con una secuencia TCP no válida (SEQ=1) y una posible bandera `RST` (Reset). Esto indica que el servidor o el sistema operativo receptor rechazó el paquete al no reconocer una conexión TCP válida.

El resultado confirma que el servidor reconoce y rechaza entradas malformadas enviadas fuera de una sesión TCP válida. Esta reacción valida que el servidor no procesa ni interpreta mensajes enviados de forma anómala o maliciosa sin conexión previa.

---

## Fuzzing 2: `NICK` con caracteres inválidos

Esta prueba evalúa la tolerancia del servidor IRC frente a comandos `NICK` malformados, específicamente aquellos que contienen caracteres inválidos o no permitidos por el estándar del protocolo. El comando `NICK` es crítico en el proceso de autenticación de los usuarios, por lo que es importante verificar la respuesta del servidor ante entradas anómalas.

Se espera que, al enviar un comando `NICK` con caracteres especiales no válidos (por ejemplo: `@`, `#`, `$`, etc.), el servidor pueda:

- Rechazar el comando por violar el formato esperado del nick.
- Cerrar la conexión por motivos de seguridad.
- Ignorar el comando sin generar respuesta.

Se utilizó Scapy para construir un paquete TCP/IP con una carga `NICK` inválida y enviarlo directamente al puerto del servidor IRC (6667) ubicado en la dirección IP `172.17.0.2`. No se realizó el handshake TCP ni un proceso de login previo.

Código utilizado:

```python
from scapy.all import *

# Construimos un mensaje NICK con caracteres inválidos
msg = "NICK @@##$$\r\n"

# Construimos el paquete IP/TCP con destino al servidor IRC
pkt = IP(dst="172.17.0.2") / TCP(dport=6667, sport=RandShort(), flags="PA") / Raw(load=msg.encode())

# Enviamos el paquete
send(pkt)
```

### Observación

Durante la ejecución y captura con Wireshark (`tcp.port == 6667`), se identificaron:

- **Paquete de solicitud:** Paquete enviado con el contenido `NICK @@##$$` visible en el campo Raw de la carga TCP.
- **Paquete TCP en rojo:** Inmediatamente después, Wireshark mostró un paquete con secuencia `SEQ: 1` y bandera `RST` (Reset). Esto indica que el servidor rechazó el paquete al no identificar una sesión TCP válida o por contenido inválido.

---

## Modificación de Paquetes Interceptados

En esta etapa se modifican dinámicamente paquetes legítimos capturados, alterando comandos estándar para analizar la tolerancia del sistema frente a comandos no válidos.

## Modificación 1: Envío de comando IRC malformado usando Scapy

Se intentó enviar un comando `NICK` con caracteres no válidos mediante un paquete TCP construido con Scapy, simulando manualmente el handshake TCP completo (SYN, SYN-ACK, ACK). El objetivo fue observar la reacción del servidor frente a un comando que infringe las reglas sintácticas del protocolo IRC.

Código utilizado:

```python
from scapy.all import *
import random
import time

# Dirección y puerto del servidor IRC
ip_dst = "172.17.0.2"
puerto_dst = 6667

# Generar puerto y número de secuencia aleatorios
puerto_src = RandShort()
seq = random.randint(1000, 50000)

# Crear capa IP
ip = IP(dst=ip_dst)

# 1. Enviar SYN
syn = TCP(sport=puerto_src, dport=puerto_dst, flags='S', seq=seq)
synack = sr1(ip/syn, timeout=2)

if synack is None or synack[TCP].flags != 'SA':
    print("No se recibió SYN-ACK. Conexión rechazada o filtrada.")
    exit()

# 2. Completar el handshake con ACK
ack_num = synack.seq + 1
seq_num = seq + 1
ack = TCP(sport=puerto_src, dport=puerto_dst, flags='A', seq=seq_num, ack=ack_num)
send(ip/ack)

# 3. Enviar comando NICK inválido
payload = b"NICK $$$$$\r\n"
push_ack = TCP(sport=puerto_src, dport=puerto_dst, flags='PA', seq=seq_num, ack=ack_num)
send(ip/push_ack/Raw(load=payload))

# 4. Actualizar número de secuencia
seq_num += len(payload)
```
---

### Observación

Wireshark muestra:

- Paquete [SYN]: Inicio del handshake TCP desde el cliente.
- Paquete [SYN, ACK]: El servidor responde aceptando la conexión.
- Paquete [RST]: El servidor cierra la conexión inmediatamente tras recibir el ACK del cliente.
- Paquete [ACK]: El cliente responde con ACK, aunque el servidor ya reseteó la sesión.
- Paquete con payload NICK: El cliente envía el comando `NICK` con caracteres inválidos (`$$$$$`), provocando un nuevo `RST`.
- Final: El servidor no procesa comandos y descarta todos los paquetes con `RST`.

---

## Modificación 2: Envío de comandos NICK y USER en sesión Scapy

Se simuló una conexión TCP válida mediante Scapy, realizando el handshake TCP completo y enviando los comandos `NICK` y `USER` secuencialmente desde un cliente construido a bajo nivel.

Código utilizado:

```python
from scapy.all import *
import random

# Datos del servidor IRC
ip_dst = "172.17.0.2"
puerto_dst = 6667

# Generar puerto de origen y número de secuencia aleatorio
puerto_src = int(RandShort())
seq = random.randint(1000, 50000)

# Crear capa IP base
ip = IP(dst=ip_dst)

# 1. Enviar SYN (inicio del handshake TCP)
syn = TCP(sport=puerto_src, dport=puerto_dst, flags='S', seq=seq)
synack = sr1(ip/syn, timeout=2)

if not synack or synack[TCP].flags != 'SA':
    print("No se recibió SYN-ACK")
    exit()

# 2. Completar handshake con ACK
ack_num = synack.seq + 1
seq_num = seq + 1
ack = TCP(sport=puerto_src, dport=puerto_dst, flags='A', seq=seq_num, ack=ack_num)
send(ip/ack)

# 3. Enviar comando NICK
nick_payload = b"NICK miNick\r\n"
push_ack = TCP(sport=puerto_src, dport=puerto_dst, flags='PA', seq=seq_num, ack=ack_num)
send(ip/push_ack/Raw(load=nick_payload))
seq_num += len(nick_payload)

# 4. Enviar comando USER
user_payload = b"USER miUser 0 * :Mi Nombre\r\n"
push_ack2 = TCP(sport=puerto_src, dport=puerto_dst, flags='PA', seq=seq_num, ack=ack_num)
send(ip/push_ack2/Raw(load=user_payload))
seq_num += len(user_payload)
```

---

### Observación

- El servidor responde normalmente a la conexión TCP.
- No se recibieron paquetes con bandera `RST` tras el envío de los comandos.
- El servidor espera la continuación del protocolo (registro completo).
- La sesión TCP permanece abierta.

---

## Modificación 3: Envío de comando JOIN válido usando Scapy

Se construyó una secuencia de paquetes TCP con Scapy para enviar comandos IRC en el orden correcto, simulando el three-way handshake TCP (SYN, SYN-ACK, ACK). Después de establecer la conexión TCP, se enviaron los comandos estándar de autenticación `NICK` y `USER`, seguidos por un comando `JOIN` con un nombre de canal válido (`#canal`).

El control explícito de números de secuencia y acuse permitió un envío manual y detallado de cada paquete con payload. Sin embargo, la sesión resultó ser no válida a ojos del servidor, probablemente debido a la ausencia de un estado de conexión TCP persistente. No se esperó ni procesó respuesta entre comandos, lo que afectó el reconocimiento de la autenticación.

Código utilizado:

```python
from scapy.all import *
import random

ip_dst = "172.17.0.2"
puerto_dst = 6667

puerto_src = int(RandShort())
seq = random.randint(1000, 50000)
ip = IP(dst=ip_dst)

# 1. Handshake TCP
syn = TCP(sport=puerto_src, dport=puerto_dst, flags='S', seq=seq)
synack = sr1(ip/syn, timeout=2)

if not synack or synack[TCP].flags != 'SA':
    print("No se recibió SYN-ACK")
    exit()

ack_num = synack.seq + 1
seq_num = seq + 1
ack = TCP(sport=puerto_src, dport=puerto_dst, flags='A', seq=seq_num, ack=ack_num)
send(ip/ack)

# 2. Enviar comandos IRC válidos: NICK, USER y JOIN
comandos = [
    b"NICK testuser
",
    b"USER testuser 0 * :Real Name
",
    b"JOIN #canal
"
]

for cmd in comandos:
    push = TCP(sport=puerto_src, dport=puerto_dst, flags='PA', seq=seq_num, ack=ack_num)
    send(ip/push/Raw(load=cmd))
    seq_num += len(cmd)
```

### Observación

- Aunque el three-way handshake fue técnicamente correcto, el servidor respondió con `RST` inmediatamente después del ACK final, lo que indica que no aceptó la sesión como válida.
- Scapy no gestiona estados internos como lo haría una pila TCP real. Por tanto, el servidor detecta que la sesión no tiene las características esperadas (ventanas, buffers, retransmisiones) y la considera inválida.
- A pesar de que los comandos IRC (`NICK`, `USER`, `JOIN`) son válidos sintácticamente, son enviados en una sesión ya cerrada, y por ello cada uno provoca una respuesta `RST`.
- Aunque útil para pruebas de paquetes individuales, Scapy no es ideal para mantener una sesión completa con gestión de estado, lo que impide una comunicación realista y sostenida con el servidor.
- Servidores como InspIRCd implementan filtros y defensas ante conexiones anómalas. Es probable que haya detectado irregularidades tras el ACK y procediera a cerrarla antes de procesar cualquier comando.

---

# Conclusión

A lo largo de las pruebas de fuzzing y modificación manual de paquetes, se ha evidenciado que el servidor IRC inspeccionado implementa medidas efectivas de seguridad y robustez frente a entradas malformadas, comandos no válidos y conexiones no autorizadas.

Los principales hallazgos incluyen:

- **Rechazo de paquetes fuera de contexto:** Todos los intentos de enviar comandos sin una sesión TCP válida fueron descartados por el servidor.
- **Desconexión inmediata ante comandos inválidos:** Comandos como `NICK` con caracteres no permitidos o secuencias malformadas provocaron un `RST` inmediato, indicando protección contra entradas potencialmente peligrosas.
- **Simulación incompleta con Scapy:** A pesar de permitir el control fino sobre los paquetes, Scapy no es capaz de mantener una sesión TCP realista debido a la falta de gestión automática del estado de la conexión, lo que limita su uso en pruebas de autenticación completa.
- **Validación estricta del protocolo IRC:** El servidor no procesa comandos IRC válidos si estos no son enviados en el contexto de una sesión correctamente establecida, sincronizada y autenticada.

Estas observaciones demuestran una implementación rigurosa del protocolo IRC y mecanismos activos de defensa ante intentos de manipulación o abuso del sistema. Las pruebas también resaltan la necesidad de herramientas más avanzadas que simulen de forma realista las sesiones TCP para llevar a cabo fuzzing o testing más profundo de servicios orientados a red.

---

## Autores

- Felipe Cuevas  
- Ignacio Antiguay
