# MVP (Java) — Manejo Inseguro de Salidas del LLM

Replica el patrón de CVE-2024-5565 (Vanna.AI) para el seminario de Fundamentos
de Seguridad, con los dos vectores marcados en el tablero de correcciones:
**SQL (1)** y **Command (2)**.

Verificado: el código compila con `javac`/`mvn` sin errores.

## Requisitos

- JDK 17+
- Maven
- Una API key de Anthropic con crédito

## Instalación y ejecución

```bash
cd mvp_java
mvn package

# Crear la base de datos de juguete
java -cp target/mvp-llm-output-handling-1.0.0-jar-with-dependencies.jar com.fdsi.mvp.DbInit

# Correr el servidor
export ANTHROPIC_API_KEY=tu_llave_aqui
java -jar target/mvp-llm-output-handling-1.0.0-jar-with-dependencies.jar
```

Abrir **http://localhost:8000**.

## Qué controla cada versión

| | Vector SQL | Vector Command |
|---|---|---|
| **Insegura** | `Statement.execute(sqlDelLLM)` directo, sin validar | `ProcessBuilder("bash","-c", comandoDelLLM)` — se interpreta como shell |
| **Segura** | `SqlValidator`: solo `SELECT`, allow-list de tablas, sin palabras clave prohibidas, conexión `?mode=ro` | `CommandValidator`: allow-list cerrada de verbos, rechazo de metacaracteres, ejecución **sin** shell |

Esto corresponde exactamente a la sección 7 del informe: 7.2 (validación
estructurada), 7.3 (mínimo privilegio) y 7.4 (sandboxing + allow-list).

## Nota de seguridad

Los payloads de la demo son intencionalmente inofensivos y locales (afectan
solo `ventas.db` y comandos de solo lectura como `ls`/`whoami`). No usar
credenciales ni bases de datos reales.
