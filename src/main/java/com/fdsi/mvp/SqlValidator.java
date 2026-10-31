package com.fdsi.mvp;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Controles de la seccion 7.2 / 7.3 del informe (validacion estructurada +
 * minimo privilegio), aplicados ANTES de ejecutar cualquier SQL generado
 * por el LLM. Esto es lo que falta en la version insegura.
 *
 * Parte la consulta en tokens en vez de buscar texto con expresiones regulares:
 * asi lo que esta dentro de una cadena no se confunde con codigo, y las
 * mayusculas mezcladas o los comentarios no sirven para esconder palabras.
 */
public class SqlValidator {

    private static final int LARGO_MAXIMO = 1000;
    private static final int TABLAS_MAXIMAS = 4; // evita productos cartesianos gigantes

    private static final Set<String> TABLAS_PERMITIDAS = Set.of("clientes", "ventas");

    private static final Set<String> PALABRAS_PROHIBIDAS = Set.of(
            "drop", "delete", "update", "insert", "alter", "create", "attach", "detach",
            "pragma", "replace", "vacuum", "reindex", "load_extension");

    private static final Set<String> COMBINACIONES = Set.of("union", "intersect", "except");

    private static final Set<String> FUNCIONES_PERMITIDAS = Set.of(
            "count", "sum", "avg", "min", "max", "round", "abs", "lower", "upper",
            "length", "coalesce", "substr", "date", "strftime");

    // Palabras clave de SQL que pueden ir antes de "(" sin ser una funcion.
    private static final Set<String> CLAVES_ANTES_DE_PARENTESIS = Set.of(
            "select", "from", "join", "where", "on", "and", "or", "not", "in", "exists",
            "having", "by", "when", "then", "else", "case", "like", "between", "distinct");

    private static final Set<String> COMPARADORES = Set.of(
            "=", "==", "!=", "<>", "<", ">", "<=", ">=", "like", "glob", "is");

    private static final Set<String> OPERADORES = Set.of("+", "-", "*", "/", "%", "||");

    private static final Set<String> LITERALES = Set.of("true", "false", "null");

    private static final Set<String> SIMBOLOS_DOBLES = Set.of("||", "<=", ">=", "<>", "!=", "==", "<<", ">>");

    // Palabras que terminan la lista de tablas: lo que sigue no es un alias.
    private static final Set<String> FIN_DE_TABLA = Set.of(
            "where", "group", "order", "limit", "having", "join", "left", "right", "inner",
            "cross", "full", "natural", "outer", "on", "using", "window");

    private enum Tipo { PALABRA, CITADO, TEXTO, NUMERO, SIMBOLO, COMENTARIO }

    private record Token(Tipo tipo, String valor) {
        boolean es(String v) {
            return (tipo == Tipo.PALABRA || tipo == Tipo.SIMBOLO) && valor.equals(v);
        }

        boolean esNombre() {
            return tipo == Tipo.PALABRA || tipo == Tipo.CITADO;
        }

        boolean esLiteral() {
            return tipo == Tipo.TEXTO || tipo == Tipo.NUMERO
                    || (tipo == Tipo.PALABRA && LITERALES.contains(valor));
        }
    }

    public record Resultado(boolean valida, String mensajeOSql) {
    }

    public static Resultado validar(String sqlOriginal) {
        String sql = sqlOriginal.trim();
        if (sql.length() > LARGO_MAXIMO) {
            return rechazo("la consulta es demasiado larga.");
        }

        List<Token> tokens;
        try {
            tokens = tokenizar(sql);
        } catch (IllegalArgumentException e) {
            return rechazo(e.getMessage());
        }

        // Los comentarios se quitan para que no escondan nada (UN/**/ION no pasa) y se
        // rechazan al final, asi el motivo muestra lo que intentaban esconder.
        boolean teniaComentarios = tokens.removeIf(t -> t.tipo() == Tipo.COMENTARIO);

        if (!tokens.isEmpty() && tokens.get(tokens.size() - 1).es(";")) {
            tokens.remove(tokens.size() - 1);
        }
        if (tokens.isEmpty()) {
            return rechazo("consulta vacia.");
        }
        for (Token t : tokens) {
            if (t.es(";")) {
                return rechazo("multiples sentencias no estan permitidas.");
            }
        }
        if (!tokens.get(0).es("select")) {
            return rechazo("solo se permiten consultas SELECT.");
        }

        String motivo = revisarPalabras(tokens);
        if (motivo == null) {
            motivo = revisarCondiciones(tokens);
        }
        if (motivo == null) {
            motivo = revisarTablas(tokens);
        }
        if (motivo == null && teniaComentarios) {
            motivo = "contiene comentarios SQL (-- o /*).";
        }
        return motivo != null ? rechazo(motivo) : new Resultado(true, sql.replaceFirst("\\s*;\\s*$", ""));
    }

    private static Resultado rechazo(String motivo) {
        return new Resultado(false, "Se rechaza: " + motivo);
    }

    /** Palabras clave, combinaciones de consultas, tablas internas y funciones. */
    private static String revisarPalabras(List<Token> t) {
        for (int i = 0; i < t.size(); i++) {
            Token token = t.get(i);
            if (!token.esNombre()) {
                continue;
            }
            if (token.valor().equals("secretos_demo") || token.valor().startsWith("sqlite_")) {
                return "la consulta referencia una tabla no autorizada.";
            }
            if (token.tipo() == Tipo.PALABRA && PALABRAS_PROHIBIDAS.contains(token.valor())) {
                return "contiene una palabra clave no permitida (" + token.valor() + ").";
            }
            if (token.tipo() == Tipo.PALABRA && COMBINACIONES.contains(token.valor())) {
                return "no se permite combinar consultas (" + token.valor() + ").";
            }
            boolean esLlamada = i + 1 < t.size() && t.get(i + 1).es("(");
            if (esLlamada && !FUNCIONES_PERMITIDAS.contains(token.valor())
                    && !CLAVES_ANTES_DE_PARENTESIS.contains(token.valor())) {
                return "funcion no permitida (" + token.valor() + ").";
            }
        }
        return null;
    }

    /** Condiciones que no dependen de los datos: la huella de una inyeccion como OR '1'='1'. */
    private static String revisarCondiciones(List<Token> t) {
        String siempreVerdadera = "condicion que no depende de los datos (posible inyeccion SQL).";
        for (int i = 1; i < t.size() - 1; i++) {
            Token actual = t.get(i);
            boolean esComparador = actual.tipo() != Tipo.TEXTO && actual.tipo() != Tipo.CITADO
                    && COMPARADORES.contains(actual.valor());
            if (esComparador) {
                Token izquierda = t.get(i - 1);
                Token derecha = t.get(i + 1).es("not") && i + 2 < t.size() ? t.get(i + 2) : t.get(i + 1);
                boolean constantes = izquierda.esLiteral() && derecha.esLiteral();
                boolean mismaColumna = izquierda.esNombre() && izquierda.equals(derecha);
                if (constantes || mismaColumna) {
                    return siempreVerdadera;
                }
            }
            if (actual.es("or")) {
                int j = i + 1;
                while (j < t.size() && (t.get(j).es("not") || t.get(j).es("("))) {
                    j++;
                }
                boolean sigueOperador = j + 1 < t.size() && (COMPARADORES.contains(t.get(j + 1).valor())
                        || OPERADORES.contains(t.get(j + 1).valor()));
                if (j < t.size() && t.get(j).esLiteral() && !sigueOperador) {
                    return siempreVerdadera;
                }
            }
        }
        return null;
    }

    /** Todas las tablas de FROM y JOIN, incluidas las listas con comas, deben estar en la allow-list. */
    private static String revisarTablas(List<Token> t) {
        int cuantas = 0;
        for (int i = 0; i < t.size(); i++) {
            if (!t.get(i).es("from") && !t.get(i).es("join")) {
                continue;
            }
            int j = i + 1;
            while (true) {
                if (j >= t.size()) {
                    return "clausula FROM incompleta.";
                }
                Token tabla = t.get(j);
                if (tabla.es("(")) {
                    // Subconsulta: sus tablas se revisan cuando el ciclo llegue a su propio FROM.
                    j = cierreDeParentesis(t, j) + 1;
                } else {
                    if (!tabla.esNombre()) {
                        return "tabla no valida en FROM.";
                    }
                    if (j + 1 < t.size() && t.get(j + 1).es(".")) {
                        return "no se permite indicar el esquema de la tabla.";
                    }
                    if (!TABLAS_PERMITIDAS.contains(tabla.valor())) {
                        return "referencia tabla fuera de la allow-list (" + tabla.valor() + ").";
                    }
                    cuantas++;
                    j++;
                }
                if (j < t.size() && t.get(j).es("as")) {
                    j++;
                }
                if (j < t.size() && t.get(j).esNombre() && !FIN_DE_TABLA.contains(t.get(j).valor())) {
                    j++; // alias
                }
                if (j < t.size() && t.get(j).es(",")) {
                    j++;
                    continue;
                }
                break;
            }
        }
        return cuantas > TABLAS_MAXIMAS ? "demasiadas tablas en la consulta." : null;
    }

    private static int cierreDeParentesis(List<Token> t, int abre) {
        int profundidad = 0;
        for (int i = abre; i < t.size(); i++) {
            if (t.get(i).es("(")) {
                profundidad++;
            } else if (t.get(i).es(")") && --profundidad == 0) {
                return i;
            }
        }
        return t.size();
    }

    private static List<Token> tokenizar(String sql) {
        List<Token> tokens = new ArrayList<>();
        int i = 0;
        int n = sql.length();
        while (i < n) {
            char c = sql.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
            } else if (Character.isISOControl(c)) {
                throw new IllegalArgumentException("contiene caracteres de control.");
            } else if (sql.startsWith("--", i)) {
                // Un LLM no necesita comentarios; en una inyeccion sirven para cortar la consulta.
                int fin = sql.indexOf('\n', i);
                i = fin < 0 ? n : fin;
                tokens.add(new Token(Tipo.COMENTARIO, ""));
            } else if (sql.startsWith("/*", i)) {
                int fin = sql.indexOf("*/", i + 2);
                i = fin < 0 ? n : fin + 2;
                tokens.add(new Token(Tipo.COMENTARIO, ""));
            } else if (c == '\'') {
                int fin = cierreDeCita(sql, i, '\'');
                tokens.add(new Token(Tipo.TEXTO, sql.substring(i + 1, fin).replace("''", "'")));
                i = fin + 1;
            } else if (c == '"' || c == '`' || c == '[') {
                int fin = cierreDeCita(sql, i, c == '[' ? ']' : c);
                tokens.add(new Token(Tipo.CITADO, sql.substring(i + 1, fin).toLowerCase()));
                i = fin + 1;
            } else if (Character.isLetter(c) || c == '_') {
                int inicio = i;
                while (i < n && (Character.isLetterOrDigit(sql.charAt(i)) || sql.charAt(i) == '_'
                        || sql.charAt(i) == '$')) {
                    i++;
                }
                tokens.add(new Token(Tipo.PALABRA, sql.substring(inicio, i).toLowerCase()));
            } else if (Character.isDigit(c)) {
                int inicio = i;
                while (i < n && (Character.isLetterOrDigit(sql.charAt(i)) || sql.charAt(i) == '.')) {
                    i++;
                }
                tokens.add(new Token(Tipo.NUMERO, sql.substring(inicio, i).toLowerCase()));
            } else if (i + 1 < n && SIMBOLOS_DOBLES.contains(sql.substring(i, i + 2))) {
                tokens.add(new Token(Tipo.SIMBOLO, sql.substring(i, i + 2)));
                i += 2;
            } else {
                tokens.add(new Token(Tipo.SIMBOLO, String.valueOf(c)));
                i++;
            }
        }
        return tokens;
    }

    /** Posicion de la cita que cierra; dos seguidas ('') son una cita escapada. */
    private static int cierreDeCita(String sql, int inicio, char cita) {
        for (int i = inicio + 1; i < sql.length(); i++) {
            if (sql.charAt(i) == cita) {
                if (cita != ']' && i + 1 < sql.length() && sql.charAt(i + 1) == cita) {
                    i++;
                } else {
                    return i;
                }
            }
        }
        throw new IllegalArgumentException("contiene texto sin cerrar (comilla desbalanceada).");
    }
}
