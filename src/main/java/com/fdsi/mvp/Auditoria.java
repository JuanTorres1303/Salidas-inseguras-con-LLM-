package com.fdsi.mvp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Registro de las decisiones del gateway: las ultimas en memoria, para la
 * interfaz, y todas en auditoria.log. Cada evento ocupa una sola linea, asi una
 * salida del LLM con saltos de linea no puede falsificar entradas del registro.
 */
final class Auditoria {

    private static final int EVENTOS_EN_MEMORIA = 8;
    private static final Path ARCHIVO = Path.of("auditoria.log");
    private static final DateTimeFormatter HORA = DateTimeFormatter.ofPattern("HH:mm:ss");

    private record Evento(String hora, String vector, String decision, String motivo, String salida) {
    }

    private static final Deque<Evento> EVENTOS = new ArrayDeque<>();
    private static int permitidas = 0;
    private static int bloqueadas = 0;

    private Auditoria() {
    }

    /** Registra una decision del gateway (solo la version segura pasa por aqui). */
    static synchronized void registrar(String vector, boolean bloqueado, String motivo, String salidaLlm) {
        Evento e = new Evento(LocalTime.now().format(HORA), vector,
                bloqueado ? "BLOQUEADO" : "PERMITIDO", unaLinea(motivo), unaLinea(salidaLlm));
        if (bloqueado) {
            bloqueadas++;
        } else {
            permitidas++;
        }
        EVENTOS.addFirst(e);
        if (EVENTOS.size() > EVENTOS_EN_MEMORIA) {
            EVENTOS.removeLast();
        }
        try {
            String linea = String.join(" | ", e.hora(), e.vector(), e.decision(), e.motivo(), e.salida()) + "\n";
            Files.writeString(ARCHIVO, linea, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ex) {
            System.err.println("[Auditoria] No se pudo escribir el registro: " + ex.getMessage());
        }
    }

    static synchronized String json() {
        StringBuilder sb = new StringBuilder("{\"permitidas\":").append(permitidas)
                .append(",\"bloqueadas\":").append(bloqueadas).append(",\"eventos\":[");
        boolean primero = true;
        for (Evento e : EVENTOS) {
            if (!primero) {
                sb.append(",");
            }
            primero = false;
            sb.append("{\"hora\":\"").append(e.hora())
                    .append("\",\"vector\":\"").append(e.vector())
                    .append("\",\"decision\":\"").append(e.decision())
                    .append("\",\"motivo\":\"").append(LlmClient.escapeJson(e.motivo()))
                    .append("\",\"salida\":\"").append(LlmClient.escapeJson(e.salida())).append("\"}");
        }
        return sb.append("]}").toString();
    }

    private static String unaLinea(String texto) {
        return texto.replaceAll("\\s+", " ").trim();
    }
}
