package com.fdsi.mvp;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Controles de la seccion 7.2 / 7.3 del informe (validacion estructurada +
 * minimo privilegio), aplicados ANTES de ejecutar cualquier SQL generado
 * por el LLM. Esto es lo que falta en la version insegura.
 */
public class SqlValidator {

    private static final Set<String> TABLAS_PERMITIDAS = Set.of("clientes", "ventas");

    private static final Pattern PALABRAS_PROHIBIDAS = Pattern.compile(
            "\\b(drop|delete|update|insert|alter|attach|pragma|replace)\\b",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern TABLAS_EN_CONSULTA = Pattern.compile(
            "\\b(?:from|join)\\s+([a-zA-Z_][a-zA-Z0-9_]*)", Pattern.CASE_INSENSITIVE);

    public record Resultado(boolean valida, String mensajeOSql) {}

    public static Resultado validar(String sqlOriginal) {
        String sql = sqlOriginal.trim();
        if (sql.endsWith(";")) {
            sql = sql.substring(0, sql.length() - 1).trim();
        }

        if (sql.contains(";")) {
            return new Resultado(false, "Se rechaza: multiples sentencias no estan permitidas.");
        }
        if (!sql.toLowerCase().startsWith("select")) {
            return new Resultado(false, "Se rechaza: solo se permiten consultas SELECT.");
        }
        if (PALABRAS_PROHIBIDAS.matcher(sql).find()) {
            return new Resultado(false, "Se rechaza: contiene una palabra clave no permitida.");
        }
        if (sql.toLowerCase().contains("secretos_demo")) {
            return new Resultado(false, "Se rechaza: la consulta referencia una tabla no autorizada.");
        }

        Matcher m = TABLAS_EN_CONSULTA.matcher(sql);
        List<String> tablas = Arrays.asList(); // placeholder para claridad de tipo
        while (m.find()) {
            String tabla = m.group(1).toLowerCase();
            if (!TABLAS_PERMITIDAS.contains(tabla)) {
                return new Resultado(false, "Se rechaza: referencia tabla fuera de la allow-list (" + tabla + ").");
            }
        }

        return new Resultado(true, sql);
    }
}
