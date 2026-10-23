package com.fdsi.mvp;

import java.util.List;
import java.util.Set;

/**
 * Controles de la seccion 7.4 del informe (sandboxing + allow-list de
 * herramientas) para el vector de inyeccion de comandos. En vez de una
 * deny-list de patrones peligrosos (facil de eludir), se permite
 * EXPLICITAMENTE solo un conjunto cerrado de comandos sin argumentos
 * peligrosos, y se ejecuta sin pasar por un interprete de shell.
 */
public class CommandValidator {

    private static final Set<String> COMANDOS_PERMITIDOS = Set.of("ls", "pwd", "date", "whoami");

    // Unico argumento aceptado: opciones de ls sobre el directorio actual
    // (-l, -a, -la, -lh...). Ninguna ruta, para no listar directorios del sistema.
    private static final String OPCIONES_LS = "-[laht1]+";

    public record Resultado(boolean valido, String mensaje, List<String> comando) {
    }

    public static Resultado validar(String comandoGenerado) {
        String limpio = comandoGenerado.trim();

        // Cualquier metacaracter de shell se rechaza de una vez: si aparece,
        // significa que el LLM intento encadenar o inyectar algo mas.
        String[] prohibidos = { ";", "&&", "||", "&", "|", "`", "$(", ">", "<", "\n" };
        for (String p : prohibidos) {
            if (limpio.contains(p)) {
                return new Resultado(false, "Se rechaza: contiene un metacaracter de shell (" + p + ").", null);
            }
        }

        if (limpio.isEmpty()) {
            return new Resultado(false, "Se rechaza: comando vacio.", null);
        }
        String[] partes = limpio.split("\\s+");

        String verbo = partes[0];
        if (!COMANDOS_PERMITIDOS.contains(verbo)) {
            return new Resultado(false, "Se rechaza: '" + verbo + "' no esta en la allow-list.", null);
        }

        for (int i = 1; i < partes.length; i++) {
            if (!verbo.equals("ls") || !partes[i].matches(OPCIONES_LS)) {
                return new Resultado(false,
                        "Se rechaza: argumento no permitido para '" + verbo + "' (" + partes[i] + ").", null);
            }
        }

        // Se ejecuta SIN shell (ProcessBuilder recibe la lista ya separada),
        // asi que aunque un argumento tuviera algo raro, no se interpreta.
        return new Resultado(true, "ok", List.of(partes));
    }
}
