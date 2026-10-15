# 🛡️ SIEM & SOAR Automático (Fase 1: Motor Lógico y Datos)
**Proyecto de Tesis:** Análisis Automatizado de Registros y Detección de Anomalías
**Autor:** Juan Cruz Pereyra Muñoz

## 📝 Descripción
Este repositorio contiene el código fuente de la lógica principal y la arquitectura de datos para un sistema de Gestión de Eventos de Seguridad (SIEM) y Respuesta Automatizada (SOAR), diseñado para integrarse con la plataforma **n8n**.

El sistema es capaz de analizar logs en texto plano (como `auth.log` de Linux), estructurarlos, aplicar reglas de detección dinámicas, consultar bases de datos de Inteligencia de Amenazas (Threat Intel) y ejecutar acciones de mitigación táctica a nivel de sistema operativo (bloqueos mediante `iptables`).

## 🏗️ Arquitectura de Archivos
La lógica se encuentra dividida en scripts de JavaScript puro, diseñados para ser ejecutados dentro de los nodos nativos `Code` del orquestador n8n:

* `01_database_setup.sql`: Estructura relacional avanzada para PostgreSQL. Contiene tablas para persistencia forense (`alerts`), seguimiento de atacantes persistentes (`attack_patterns`) y reglas dinámicas para n8n (`detection_rules`).
* `01_nodo_ingesta.js`: Script de lectura de archivos que interactúa con el sistema de archivos del SO (`fs`) para extraer únicamente los logs generados en los últimos 5 minutos.
* `02_nodo_parser.js`: Motor de normalización que utiliza Expresiones Regulares (Regex) complejas para extraer metadatos estructurados (IPs, usernames, comandos sudo) a partir del texto plano de los logs.
* `03_nodo_rules_engine.js`: Cerebro del sistema que cruza los logs parseados contra las reglas almacenadas en la base de datos para determinar si se supera el umbral (Threshold) dentro de una ventana de tiempo (Time Window) específica.
* `04_nodo_threat_intel.js`: Módulo de enriquecimiento que consulta a la API de **AbuseIPDB** y eleva la severidad de las alertas si la IP atacante es una amenaza global conocida.
* `05_nodo_respuesta_activa.js`: El componente SOAR. Ejecuta comandos de sistema (`child_process`) para modificar las reglas de firewall (iptables) y bloquear activamente a los atacantes reincidentes.

## 🚀 Requisitos Previos para Despliegue en n8n
Para que estos scripts de JavaScript se ejecuten correctamente en un entorno Dockerizado de n8n, es **obligatorio** configurar la siguiente variable de entorno en el archivo `docker-compose.yml` para permitir el acceso a módulos externos nativos y de terceros:

```env
NODE_FUNCTION_ALLOW_EXTERNAL=pg,axios,fs,readline,child_process,util