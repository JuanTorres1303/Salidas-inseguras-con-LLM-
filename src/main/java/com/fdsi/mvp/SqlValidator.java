package com.fdsi.mvp;

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
            "\\b(drop|delete|update|insert|alter|attach|detach|pragma|replace|vacuum|load_extension)\\b",
            Pattern.CASE_INSENSITIVE);

    // Captura lo que viene despues de FROM o JOIN hasta la siguiente palabra
    // clave, parentesis o fin de la consulta. Asi se revisan TODAS las tablas
    // de una lista separada por comas (FROM clientes, sqlite_master) y las de
    // las subconsultas, que se capturan en su propio FROM.
    private static final Pattern CLAUSULA_TABLAS = Pattern.compile(
            "\\b(?:from|join)\\b(.*?)(?=\\b(?:where|group|order|limit|having|union|except|intersect"
            + "|join|on|using|natural|left|right|inner|cross|outer|full|select|from|window)\\b|[()]|$)",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

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

        Matcher m = CLAUSULA_TABLAS.matcher(sql);
        while (m.find()) {
            for (String parte : m.group(1).split(",")) {
                String texto = parte.trim();
                if (texto.isEmpty()) {
                    continue; // p. ej. "FROM (" de una subconsulta: su tabla se revisa en su propio FROM
                }
                // Primer token = nombre de la tabla (lo demas es el alias).
                String tabla = texto.split("\\s+")[0].replaceAll("[\"`\\[\\]]", "").toLowerCase();
                if (!TABLAS_PERMITIDAS.contains(tabla)) {
                    return new Resultado(false, "Se rechaza: referencia tabla fuera de la allow-list (" + tabla + ").");
                }
            }
        }

        return new Resultado(true, sql);
    }
}
