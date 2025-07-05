# Taller-Tarea3: Inyección y Modificación de Tráfico en Protocolo IRC con Scapy

Este proyecto extiende el trabajo realizado en la Tarea 2, enfocándose en el análisis y manipulación del tráfico IRC utilizando **Scapy**. Se estudia el comportamiento del servidor y cliente IRC frente a la inyección o modificación de tráfico no esperado, con el objetivo de explorar vulnerabilidades o reacciones del sistema ante datos anómalos.

---

## Tabla de contenido

- [Información general](#información-general)
- [Tecnologías utilizadas](#tecnologías-utilizadas)
- [Instalación del entorno](#instalación-del-entorno)
- [Uso de Scapy para inyección y modificación](#uso-de-scapy-para-inyección-y-modificación)
- [Casos de prueba y análisis](#casos-de-prueba-y-análisis)
- [Reproducción del experimento](#reproducción-del-experimento)
- [Video demostrativo](#video-demostrativo)
- [Autores](#autores)

---

## Información general

El objetivo de esta tarea es interceptar, inyectar y modificar tráfico IRC entre un cliente y un servidor, utilizando herramientas como **Scapy**. A través de estas modificaciones, se pretende observar y documentar los efectos sobre el comportamiento del servicio.

**Objetivos específicos:**

- Inyectar tráfico no esperado usando Scapy.
- Modificar campos del protocolo para provocar respuestas anómalas.
- Analizar el comportamiento del servidor y del cliente frente a estos cambios.
- Formular hipótesis en los casos donde no se obtuvo el efecto deseado.

---

## Tecnologías utilizadas

- Docker 24.0+
- InspIRCd (Servidor IRC)
- irssi (Cliente IRC)
- Scapy (Python)
- Terminal bash
- Sistema operativo Linux

---

## Instalación del entorno

### Servidor IRC

```bash
docker run -d --name irc-server -p 6667:6667 inspircd/inspircd-docker
```

### Cliente IRC

```bash
docker run -it --name irc-client --network host irssi
```

### Contenedor con Scapy

```bash
docker run -it --name scapy --network host --cap-add=NET_ADMIN --cap-add=NET_RAW scapy/scapy
```

---

## Uso de Scapy para inyección y modificación

Los scripts de Scapy se encuentran en la carpeta `scripts/`. A continuación, se describe brevemente cómo ejecutarlos:

```bash
python3 scripts/inyeccion_fuzzing1.py
python3 scripts/modificacion_nick.py
python3 scripts/inyeccion_sin_user.py
```

Cada script representa una prueba de inyección o modificación del protocolo IRC con diferentes fines.

---

## Casos de prueba y análisis

### Inyecciones con técnicas de fuzzing

1. **Fuzzing sobre comando NICK inválido**  
   - Resultado: el servidor responde con `:Erroneous Nickname` y posteriormente cierra la conexión mediante un paquete TCP con bandera `RST`.

2. **Payload no estructurado hacia el servidor IRC**  
   - Resultado: el paquete es ignorado o no se procesa; no hay respuesta visible en los logs.

### Modificaciones del protocolo

1. **Campo NICK con caracteres ilegales**  
   - Expectativa: el servidor rechaza el comando.
   - Resultado: se obtuvo respuesta de error (`:Erroneous Nickname`) y cierre de la conexión.

2. **Modificación del número de secuencia TCP**  
   - Expectativa: el servidor detecta una anomalía.
   - Resultado: conexión cerrada con `RST`, sin procesamiento del paquete.

3. **Inyección de comando sin completar autenticación (sin USER)**  
   - Expectativa: el servidor no reconoce al remitente como autenticado.
   - Resultado: el comando es ignorado y la conexión eventualmente se cierra.

---

## Reproducción del experimento

### Clonación del repositorio

```bash
git clone <URL_DEL_REPOSITORIO>
cd tarea3-irc
```

### Levantar el entorno

```bash
docker start irc-server
docker start -ai irc-client
```

### Ejecutar scripts de Scapy

```bash
docker start -ai scapy
python3 scripts/<nombre_del_script>.py
```

Asegúrate de tener privilegios suficientes para usar interfaces de red sin restricciones en el contenedor Scapy.

---

## Video demostrativo

El video explicativo del proyecto se encuentra en el siguiente enlace:

🔗 [YouTube - Tarea 3: Scapy + IRC](https://www.youtube.com/...)

---

## Autores

- Felipe Cuevas  
- Ignacio Antiguay
