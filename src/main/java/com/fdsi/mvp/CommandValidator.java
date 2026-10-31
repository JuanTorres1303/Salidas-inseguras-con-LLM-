package com.fdsi.mvp;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Controles de la seccion 7.4 del informe (sandboxing + allow-list de
 * herramientas) para el vector de inyeccion de comandos. En vez de una
 * deny-list de patrones peligrosos (facil de eludir), se permite
 * EXPLICITAMENTE solo un conjunto cerrado de comandos sin argumentos
 * peligrosos, y se ejecuta sin pasar por un interprete de shell.
 */
public class CommandValidator {

    private static final int LARGO_MAXIMO = 60;

    private static final Set<String> COMANDOS_PERMITIDOS = Set.of("ls", "pwd", "date", "whoami");

    // Unicos argumentos aceptados, y solo para ls: opciones (-l, -a, -la, -lh...)
    // y carpetas del proyecto. Ninguna ruta, para no listar directorios del sistema.
    private static final String OPCIONES_LS = "-[laht1]+";
    private static final Set<String> CARPETAS_PERMITIDAS = Set.of("src", "target");

    // Allow-list de caracteres: cubre lo que una lista de metacaracteres no alcanza
    // a nombrar (comillas, variables, variantes Unicode, rutas con ../, etc.).
    private static final Pattern CARACTERES_PERMITIDOS = Pattern.compile("[a-zA-Z0-9 -]+");

    public record Resultado(boolean valido, String mensaje, List<String> comando) {
    }

    public static Resultado validar(String comandoGenerado) {
        String limpio = comandoGenerado.trim();

        if (limpio.isEmpty()) {
            return rechazo("comando vacio.");
        }
        if (limpio.length() > LARGO_MAXIMO) {
            return rechazo("comando demasiado largo.");
        }

        // Cualquier metacaracter de shell se rechaza de una vez: si aparece,
        // significa que el LLM intento encadenar o inyectar algo mas.
        String[] prohibidos = { ";", "&&", "||", "&", "|", "`", "$(", "${", ">", "<", "\n", "\r" };
        for (String p : prohibidos) {
            if (limpio.contains(p)) {
                String visible = p.replace("\n", "salto de linea").replace("\r", "retorno de carro");
                return rechazo("contiene un metacaracter de shell (" + visible + ").");
            }
        }
        if (!CARACTERES_PERMITIDOS.matcher(limpio).matches()) {
            return rechazo("contiene caracteres no permitidos.");
        }

        String[] partes = limpio.split("\\s+");

        String verbo = partes[0];
        if (!COMANDOS_PERMITIDOS.contains(verbo)) {
            return rechazo("'" + verbo + "' no esta en la allow-list.");
        }

        for (int i = 1; i < partes.length; i++) {
            boolean permitido = verbo.equals("ls")
                    && (partes[i].matches(OPCIONES_LS) || CARPETAS_PERMITIDAS.contains(partes[i]));
            if (!permitido) {
                return rechazo("argumento no permitido para '" + verbo + "' (" + partes[i] + ").");
            }
        }

        // Se ejecuta SIN shell (ProcessBuilder recibe la lista ya separada),
        // asi que aunque un argumento tuviera algo raro, no se interpreta.
        return new Resultado(true, "ok", List.of(partes));
    }

    private static Resultado rechazo(String motivo) {
        return new Resultado(false, "Se rechaza: " + motivo, null);
    }
}
