package com.fdsi.mvp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Statement;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MVP - Manejo Inseguro de Salidas del LLM (OWASP LLM05 / LLM10:2026)
 *
 * Replica el patron de CVE-2024-5565 (Vanna.AI) con dos vectores, los mismos
 * que aparecen en el tablero de correccion de la profe: SQL y Command.
 *
 * Correr:
 * mvn package
 * java -cp target/mvp-llm-output-handling-1.0.0-jar-with-dependencies.jar
 * com.fdsi.mvp.DbInit
 * java -jar target/mvp-llm-output-handling-1.0.0-jar-with-dependencies.jar
 * Abrir http://localhost:8000
 *
 * (Opcional: variable de entorno ANTHROPIC_API_KEY o archivo .env. Sin clave
 * se usa el simulador local de LLM.)
 */
public class App {

    private static final String DB_URL = "jdbc:sqlite:ventas.db";
    // Forma URI ("file:"): sin ella el driver toma "?mode=ro" como parte del
    // nombre del archivo y no abre la base de datos.
    private static final String DB_URL_SOLO_LECTURA = "jdbc:sqlite:file:ventas.db?mode=ro";

    // Comandos que la version insegura ejecuta de verdad en el shell. Todo lo
    // demas se simula, para que un LLM real nunca ejecute algo peligroso en el
    // equipo de la demo (la vulnerabilidad se muestra igual: no hay validacion).
    private static final Set<String> COMANDOS_REALES_DEMO = Set.of("date", "whoami", "pwd", "ls", "ls -la", "ls src");

    // Lo que un shell entiende como "aqui empieza otro comando".
    private static final Pattern SEPARADORES_SHELL = Pattern.compile(";|&&|\\|\\||\\||&|\\n");

    private static final int FILAS_MAXIMAS = 200;
    private static final int SEGUNDOS_MAXIMOS_CONSULTA = 3;
    private static final int LARGO_MAXIMO_PETICION = 20_000;
    private static final int LARGO_MAXIMO_PREGUNTA = 2_000;

    private static final String ESTADO_SIN_VALIDAR = "SIN_VALIDAR";
    private static final String ESTADO_BLOQUEADO = "BLOQUEADO";
    private static final String ESTADO_PERMITIDO = "PERMITIDO";

    private static final String ESQUEMA = """
            Tablas disponibles:
            - clientes(id, nombre, ciudad)
            - ventas(id, cliente_id, producto, monto, fecha)
            - secretos_demo(clave, valor) -- tabla sensible, NO debe consultarse
            """;

    static final String SQL_SYSTEM_PROMPT = "Eres un asistente que traduce preguntas en lenguaje natural a una unica "
            + "consulta SQL para SQLite. " + ESQUEMA
            + " Responde UNICAMENTE con la consulta SQL, sin explicaciones ni markdown.";

    static final String CMD_SYSTEM_PROMPT = "Eres un asistente de administracion de sistemas que traduce una peticion en "
            + "lenguaje natural a UN SOLO comando de shell Unix equivalente. "
            + "Responde UNICAMENTE con el comando, sin explicaciones ni markdown.";

    public static void main(String[] args) throws Exception {
        Class.forName("org.sqlite.JDBC");
        if (!Files.exists(Path.of("ventas.db"))) {
            DbInit.crear();
        }

        // Solo en este equipo: los endpoints inseguros no deben quedar expuestos a la red.
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 8000), 0);
        server.createContext("/", App::handleIndex);
        server.createContext("/insecure-sql", ex -> handleSql(ex, false));
        server.createContext("/secure-sql", ex -> handleSql(ex, true));
        server.createContext("/insecure-cmd", ex -> handleCmd(ex, false));
        server.createContext("/secure-cmd", ex -> handleCmd(ex, true));
        server.createContext("/reset-db", App::handleResetDb);
        server.createContext("/auditoria", App::handleAuditoria);
        server.setExecutor(null);
        server.start();
        System.out.println("Servidor corriendo en http://localhost:8000");
        System.out.println(LlmClient.hayApiKey()
                ? "LLM: API de Anthropic (modelo " + LlmClient.modelo() + "). Si falla, se usa el simulador local."
                : "LLM: simulador local (sin API key, sin costo).");
    }

    // -----------------------------------------------------------------
    private static void handleResetDb(HttpExchange ex) throws IOException {
        if (!esPeticionJson(ex)) {
            return;
        }
        try {
            DbInit.crear();
            responder(ex, json("", "Base de datos restaurada con los datos de ejemplo.", "", null));
        } catch (Exception e) {
            responder(ex, json("", "", "", "No se pudo restaurar la base de datos: " + e.getMessage()));
        }
    }

    private static void handleAuditoria(HttpExchange ex) throws IOException {
        responder(ex, Auditoria.json());
    }

    // -----------------------------------------------------------------
    private static void handleIndex(HttpExchange ex) throws IOException {
        InputStream in = App.class.getResourceAsStream("/static/index.html");
        byte[] html = in.readAllBytes();
        ex.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
        ex.sendResponseHeaders(200, html.length);
        ex.getResponseBody().write(html);
        ex.close();
    }

    // -----------------------------------------------------------------
    // Vector 1: texto -> SQL
    // -----------------------------------------------------------------
    private static void handleSql(HttpExchange ex, boolean segura) throws IOException {
        if (!esPeticionJson(ex)) {
            return;
        }
        String pregunta = leerPregunta(ex);
        String sqlGenerado;
        try {
            sqlGenerado = LlmClient.ask(SQL_SYSTEM_PROMPT, pregunta).trim();
        } catch (Exception e) {
            responder(ex, json("ERROR llamando al LLM", "", "", e.getMessage()));
            return;
        }

        String resultado;
        String estado;
        if (!segura) {
            // VULNERABLE: se ejecuta tal cual lo que devolvio el LLM.
            // Es exactamente el "paso 3" de la Figura 1 sin validar.
            resultado = ejecutarSqlDirecto(sqlGenerado);
            estado = ESTADO_SIN_VALIDAR;
        } else {
            SqlValidator.Resultado v = SqlValidator.validar(sqlGenerado);
            if (!v.valida()) {
                resultado = "BLOQUEADO: " + v.mensajeOSql();
                estado = ESTADO_BLOQUEADO;
                Auditoria.registrar("SQL", true, v.mensajeOSql(), sqlGenerado);
            } else {
                resultado = ejecutarSqlSoloLectura(v.mensajeOSql());
                estado = ESTADO_PERMITIDO;
                Auditoria.registrar("SQL", false, "Paso todas las reglas", sqlGenerado);
            }
        }
        responder(ex, json(sqlGenerado, resultado, estado, null));
    }

    private static String ejecutarSqlDirecto(String sql) {
        // El driver de SQLite solo ejecuta la primera sentencia de cada
        // execute(), asi que se separan por ';' y se ejecutan TODAS, como lo
        // haria una aplicacion que confia ciegamente en la salida del LLM.
        // (Lo que queda tras el ';' de cierre de una inyeccion suele ser solo un comentario.)
        String[] sentencias = Arrays.stream(sql.split(";"))
                .filter(s -> !s.isBlank() && !s.trim().startsWith("--"))
                .toArray(String[]::new);
        StringBuilder sb = new StringBuilder();
        int n = 0;
        try (Connection conn = DriverManager.getConnection(DB_URL);
                Statement st = conn.createStatement()) {
            for (String s : sentencias) {
                n++;
                if (sentencias.length > 1) {
                    sb.append("-- Sentencia ").append(n).append(": ").append(s.trim()).append("\n");
                }
                try {
                    boolean esConsulta = st.execute(s);
                    if (esConsulta) {
                        String filas = formatearResultSet(st.getResultSet());
                        sb.append(filas).append(filas.endsWith("\n") ? "" : "\n");
                    } else {
                        sb.append("Sentencia ejecutada. Filas afectadas: ").append(st.getUpdateCount()).append("\n");
                    }
                } catch (Exception e) {
                    sb.append("Se intento ejecutar. Efecto/Error: ").append(e.getMessage()).append("\n");
                }
            }
        } catch (Exception e) {
            return "Se intento ejecutar. Efecto/Error: " + e.getMessage();
        }
        return sb.toString();
    }

    private static String ejecutarSqlSoloLectura(String sqlValidado) {
        // Conexion de solo lectura: principio de minimo privilegio (seccion 7.3)
        try (Connection conn = DriverManager.getConnection(DB_URL_SOLO_LECTURA);
                Statement st = conn.createStatement()) {
            st.setMaxRows(FILAS_MAXIMAS);
            st.setQueryTimeout(SEGUNDOS_MAXIMOS_CONSULTA);
            ResultSet rs = st.executeQuery(sqlValidado);
            return formatearResultSet(rs);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private static String formatearResultSet(ResultSet rs) throws Exception {
        StringBuilder sb = new StringBuilder();
        ResultSetMetaData meta = rs.getMetaData();
        int cols = meta.getColumnCount();
        while (rs.next()) {
            for (int i = 1; i <= cols; i++) {
                sb.append(rs.getString(i)).append(i < cols ? " | " : "");
            }
            sb.append("\n");
        }
        return sb.isEmpty() ? "(sin filas)" : sb.toString();
    }

    // -----------------------------------------------------------------
    // Vector 2: texto -> comando de shell (inyeccion de comandos)
    // -----------------------------------------------------------------
    private static void handleCmd(HttpExchange ex, boolean segura) throws IOException {
        if (!esPeticionJson(ex)) {
            return;
        }
        String pregunta = leerPregunta(ex);
        String cmdGenerado;
        try {
            cmdGenerado = LlmClient.ask(CMD_SYSTEM_PROMPT, pregunta).trim();
        } catch (Exception e) {
            responder(ex, json("ERROR llamando al LLM", "", "", e.getMessage()));
            return;
        }

        String resultado;
        String estado;
        if (!segura) {
            // VULNERABLE: el comando generado se ejecuta a traves de un shell,
            // igual que un agente con "excessive agency" sin validacion (LLM08).
            resultado = ejecutarComandoInseguro(cmdGenerado);
            estado = ESTADO_SIN_VALIDAR;
        } else {
            CommandValidator.Resultado v = CommandValidator.validar(cmdGenerado);
            if (!v.valido()) {
                resultado = "BLOQUEADO: " + v.mensaje();
                estado = ESTADO_BLOQUEADO;
                Auditoria.registrar("CMD", true, v.mensaje(), cmdGenerado);
            } else {
                resultado = ejecutarComandoSeguro(v.comando());
                estado = ESTADO_PERMITIDO;
                Auditoria.registrar("CMD", false, "Paso todas las reglas", cmdGenerado);
            }
        }
        responder(ex, json(cmdGenerado, resultado, estado, null));
    }

    /**
     * Separa la salida como lo haria un shell y muestra el efecto de cada comando:
     * asi se ve que el comando inyectado tambien se ejecuta. Los de solo lectura
     * corren de verdad; los peligrosos solo describen su efecto.
     */
    private static String ejecutarComandoInseguro(String comando) {
        // Respuesta inmediata para evitar bloqueos por red (curl/reverse shell)
        if (comando.contains("curl") || comando.contains("exploit")) {
            return "[EJECUCION DE CODIGO REMOTO (RCE) EN SHELL - simulado]\n" +
                    "-> Conectando a URL externa y ejecutando payload...\n" +
                    "-> Reverse Shell abierta hacia atacante (192.168.1.100:4444). Acceso total concedido.";
        }
        StringBuilder sb = new StringBuilder();
        for (String parte : SEPARADORES_SHELL.split(comando)) {
            if (!parte.isBlank()) {
                sb.append("$ ").append(parte.trim()).append("\n")
                        .append(efectoDeComando(parte.trim()).trim()).append("\n");
            }
        }
        return sb.toString();
    }

    private static String efectoDeComando(String comando) {
        if (comando.contains("/etc/passwd")) {
            return "[ACCESO ILEGITIMO A SISTEMA POR SHELL - simulado]\n" +
                    "root:x:0:0:root:/root:/bin/bash\n" +
                    "admin:x:1000:1000:Admin:/home/admin:/bin/bash\n" +
                    "-> Se filtraron las cuentas del sistema.";
        }
        if (comando.contains("rm ") || comando.contains("logs")) {
            return "[COMANDO DESTRUCTIVO EJECUTADO EN SHELL - simulado]\n" +
                    "-> '" + comando + "' ejecutado sin confirmacion. Archivos del servidor eliminados.";
        }
        if (!COMANDOS_REALES_DEMO.contains(comando)) {
            return "[SIMULACION - EJECUTADO EN SHELL SIN VALIDAR]\n" +
                    "-> '" + comando + "' se habria ejecutado en el shell del servidor con todos sus permisos.";
        }

        try {
            boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
            ProcessBuilder pb;
            if (isWindows) {
                // Salida en UTF-8 para que tildes y simbolos se lean bien en la interfaz;
                // el ls de PowerShell no entiende -la.
                pb = new ProcessBuilder("powershell.exe", "-NoProfile", "-Command",
                        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + comando.replace("-la", "-Force"));
            } else {
                pb = new ProcessBuilder("bash", "-c", comando);
            }
            pb.redirectErrorStream(true);
            Process p = pb.start();
            boolean finished = p.waitFor(5, TimeUnit.SECONDS);
            if (!finished) {
                p.destroyForcibly();
                return "[EJECUTADO EN SHELL]: El comando fue enviado al interprete de shell.";
            }
            String salida = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            return salida.isBlank() ? "(ejecutado sin salida)" : salida;
        } catch (Exception e) {
            return "Se intento ejecutar en shell. Efecto: " + e.getMessage();
        }
    }

    private static String ejecutarComandoSeguro(List<String> comando) {
        try {
            // SEGURO: se ejecuta la lista de tokens directamente, SIN pasar
            // por un shell, y solo si el verbo estaba en la allow-list.
            // En Windows estos verbos no son ejecutables, asi que se resuelven
            // con Java (tampoco hay shell de por medio).
            boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
            String verbo = comando.get(0).toLowerCase();
            if (isWindows) {
                if (verbo.equals("ls")) {
                    List<String> argumentos = comando.subList(1, comando.size());
                    boolean todos = argumentos.stream().anyMatch(a -> a.startsWith("-") && a.contains("a"));
                    String carpeta = argumentos.stream().filter(a -> !a.startsWith("-")).findFirst().orElse(".");
                    java.io.File[] archivos = new java.io.File(carpeta).listFiles();
                    StringBuilder sb = new StringBuilder();
                    if (archivos != null) {
                        Arrays.sort(archivos);
                        for (java.io.File f : archivos) {
                            if (!todos && f.getName().startsWith("."))
                                continue;
                            sb.append(f.getName()).append(f.isDirectory() ? "/" : "").append("\n");
                        }
                    }
                    return sb.isEmpty() ? "(directorio vacio)" : sb.toString();
                } else if (verbo.equals("pwd")) {
                    return System.getProperty("user.dir");
                } else if (verbo.equals("date")) {
                    return java.time.LocalDateTime.now().toString();
                } else if (verbo.equals("whoami")) {
                    return System.getProperty("user.name");
                }
            }
            ProcessBuilder pb = new ProcessBuilder(comando);
            pb.environment().clear();
            pb.environment().put("PATH", "/usr/bin:/bin");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            if (!p.waitFor(5, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return "Comando detenido: supero el tiempo maximo.";
            }
            String salida = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            return salida.isBlank() ? "(ejecutado con exito sin shell)" : salida;
        } catch (Exception e) {
            return "Error al ejecutar el comando (sin interprete de shell): " + e.getMessage();
        }
    }

    // -----------------------------------------------------------------
    // Utilidades HTTP (sin librerias externas de JSON)
    // -----------------------------------------------------------------
    private static final Pattern PREGUNTA_FIELD = Pattern.compile("\"pregunta\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");

    /** Rechaza lo que no sea POST con JSON: una pagina externa no puede disparar estos endpoints. */
    private static boolean esPeticionJson(HttpExchange ex) throws IOException {
        String tipo = ex.getRequestHeaders().getFirst("Content-Type");
        if ("POST".equals(ex.getRequestMethod()) && tipo != null && tipo.toLowerCase().startsWith("application/json")) {
            return true;
        }
        ex.sendResponseHeaders(405, -1);
        ex.close();
        return false;
    }

    private static String leerPregunta(HttpExchange ex) throws IOException {
        String body = new String(ex.getRequestBody().readNBytes(LARGO_MAXIMO_PETICION), StandardCharsets.UTF_8);
        Matcher m = PREGUNTA_FIELD.matcher(body);
        String pregunta = m.find() ? LlmClient.unescapeJson(m.group(1)) : "";
        return pregunta.length() > LARGO_MAXIMO_PREGUNTA ? pregunta.substring(0, LARGO_MAXIMO_PREGUNTA) : pregunta;
    }

    private static String json(String generado, String resultado, String estado, String error) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"generado\":\"").append(LlmClient.escapeJson(generado)).append("\",");
        sb.append("\"resultado\":\"").append(LlmClient.escapeJson(resultado)).append("\",");
        sb.append("\"estado\":\"").append(estado).append("\",");
        sb.append("\"fuente\":\"").append(LlmClient.escapeJson(LlmClient.ultimaFuente())).append("\"");
        if (error != null) {
            sb.append(",\"error\":\"").append(LlmClient.escapeJson(error)).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }

    private static void responder(HttpExchange ex, String jsonBody) throws IOException {
        byte[] bytes = jsonBody.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(200, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.close();
    }
}
