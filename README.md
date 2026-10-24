# Mini Security Gateway de Salida para LLMs

Seminario de **Fundamentos de Seguridad de la Información** — Manejo inseguro de salidas de un LLM
(OWASP LLM05: Improper Output Handling).

## Enfoque del proyecto

Construimos un **mini security gateway de salida**: intercepta lo que genera el LLM, lo valida
contra una allow-list y lo ejecuta con mínimo privilegio. Es el núcleo de lo que sería un Security
Gateway completo para LLMs.

## El problema

Muchas aplicaciones le piden a un LLM que convierta lenguaje natural en una consulta SQL o en un
comando del sistema, y ejecutan directamente lo que el modelo responde. Si la petición es
maliciosa o el modelo se equivoca, el LLM genera una salida peligrosa y la aplicación la ejecuta
con sus propios permisos. Es el mismo patrón del caso real **CVE-2024-5565 (Vanna.AI)**.

La idea central del seminario: **la salida del LLM es entrada no confiable** y debe validarse antes
de ejecutarse.

## Qué logramos

- Una aplicación web que muestra **dos vectores de ataque**, cada uno en versión insegura y segura,
  lado a lado:
  - **SQL Injection:** el LLM genera consultas SQL sobre una base de datos de ventas.
  - **Command Injection:** el LLM genera comandos del sistema operativo.
- **Versión insegura:** ejecuta lo que el LLM genera, sin validar. Se ve cómo un ataque borra
  datos, filtra información sensible o compromete el servidor.
- **Versión segura (el mini gateway):** dos capas de defensa.
  1. **Validación de la salida** con allow-list: solo consultas de lectura sobre tablas
     autorizadas y solo comandos permitidos, sin encadenamientos.
  2. **Mínimo privilegio:** la base de datos se abre en solo lectura y los comandos se ejecutan sin
     intérprete de shell.
- **Ejemplos listos en la interfaz:** casos legítimos y ataques (borrado, fuga de datos, múltiples
  sentencias, concatenación de comandos, borrado de archivos, reverse shell).
- **Resistente a evasiones:** el gateway también bloquea variantes como tablas ocultas en listas o
  subconsultas, comandos en segundo plano y argumentos peligrosos.
- **Base de datos de prueba** con 10 clientes, 30 ventas y credenciales ficticias como objetivo de
  los ataques, restaurable con un botón desde la interfaz.
- **Medición automática de la seguridad:** un benchmark de 58 casos muestra que los ataques pasan de
  un 97 % de éxito sin gateway a un **0 %** con gateway, con un 4,8 % de falsos positivos y menos de
  10 microsegundos agregados por petición.
- **Modo simulación:** funciona sin API key ni costo. Opcionalmente puede usar un LLM real.
- **Demo segura:** los ataques de comandos más peligrosos se simulan y los de SQL afectan solo una
  base de datos local desechable.

## Cómo correrlo

Requisitos: **Java JDK 17+** y **Maven 3.8+**.

En PowerShell, desde la carpeta del proyecto:

```powershell
# Modo simulación (sin costo)
Remove-Item Env:ANTHROPIC_API_KEY -ErrorAction SilentlyContinue

# 1. Crear o reiniciar la base de datos de prueba
mvn compile exec:java "-Dexec.mainClass=com.fdsi.mvp.DbInit"

# 2. Levantar el servidor
mvn compile exec:java
```

Abrir **http://localhost:8000**, elegir un ejemplo y pulsar **"Ejecutar Ambos"** para comparar la
versión insegura con la segura. Detener con `Ctrl+C`.

Después de probar los ataques de borrado en la versión insegura, pulsar **"♻️ Restaurar base de
datos"** en la interfaz (o repetir el paso 1).

Para medir la seguridad (no necesita el servidor ni modifica `ventas.db`):

```powershell
mvn compile exec:java "-Dexec.mainClass=com.fdsi.mvp.Benchmark"
```

## Más detalle

La documentación completa del MVP (arquitectura, controles, casos de la demo, métricas,
estadísticas, impacto en otros sistemas de la organización y guion de presentación) está en
[`MVP.md`](MVP.md). El análisis costo-beneficio está en [`COSTOS.md`](COSTOS.md).
