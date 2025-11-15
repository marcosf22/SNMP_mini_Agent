# Mini SNMP Agent with Notifications

<p align="center">
  <img src="https://media.tenor.com/McPQygGOuXYAAAAj/gladgers-hacker-gers-guardians-of-galaxy.gif" alt="Banner del Proyecto" width="150"/>
</p>

> Este proyecto es un agente SNMP que monitoriza la CPU y resuelve la necesidad de enviar alertas proactivas (TRAP y email) cuando esta supera un umbral, en lugar de requerir un sondeo manual.

---

## 🌟 Las principales características del proyecto son:

* MIB personalizada para gestionar la CPU (MIB_AGENT.mib).
* Soporte para operaciones SNMP (GET, GETNEXT, WALK, SET).
* Monitorización activa de la CPU.
* Sistema de alertas doble (Trap y Email).
* Persistencia de datos (mib_state.json).

---

## 📁 Archivos necesarios:

* **MIB_AGENT.mib** Este archivo define el agente. En él se establecen los OIDs que existen, que tipo de datos manejan y que notificaciones se pueden mandar. 

<p align="center">
  <img src="./images/mib_tree.png" alt="Captura de pantalla 1" width="400"/>
</p>

_MIB_AGENT.mib compilado en MIB Browser._

* **mib_state.json** Este archivo es la base de datos del agente. Almacena el valor actual de los objetos definidos en la mib. Cuando el agente se reincia, este archivo le permite recordar los valores que había configurado.

* **mini_agent.py** Este es el programa principal que se ejecuta. Actúa como un servidor que se queda escuchando peticiones SNMP (GET, SET, GETNEXT) en el puerto 161. También inicia el monitor de CPU y es responsable de enviar las alertas (TRAP y email) cuando el umbral se supera.

* **test_agent.py** Este es un programa separado que actúa como un "cliente" o "manager" de red. Su único propósito es probar que el mini_agent.py funciona. Envía peticiones SNMP (GET, SET) al agente y comprueba que las respuestas sean correctas, simulando ser una herramienta de gestión de red.

<p align="center">
  <img src="./images/test.png" alt="Captura de pantalla 1" width="400"/>
</p>

_Ejemplo ejecución test_agent.py._

---

## 🚀 Cómo Empezar

Sigue estos pasos para tener una copia local del proyecto funcionando.

### 1. Prerrequisitos

* [Software 1 (ej: Python 3.10+)](https://www.python.org/)
* [Software 2 (ej: pip)](https://pip.pypa.io/en/stable/installation/)

### 2. Instalación

1.  Clona el repositorio:
    ```bash
    git clone [https://github.com/tu-usuario/tu-proyecto.git](https://github.com/tu-usuario/tu-proyecto.git)
    ```
2.  Navega al directorio del proyecto:
    ```bash
    cd tu-proyecto
    ```
3.  Instala las dependencias:
    ```bash
    pip install -r requirements.txt
    ```

### 3. Ejecución

Describe cómo ejecutar tu programa.

```bash
python mi_programa.py
