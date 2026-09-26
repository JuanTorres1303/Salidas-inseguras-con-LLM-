package com.fdsi.mvp;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

/**
 * Crea ventas.db con datos de ejemplo. Correr una sola vez:
 *   mvn compile exec:java -Dexec.mainClass=com.fdsi.mvp.DbInit
 * o, con el jar ya empaquetado:
 *   java -cp target/mvp-llm-output-handling-1.0.0-jar-with-dependencies.jar com.fdsi.mvp.DbInit
 */
public class DbInit {

    public static void main(String[] args) throws Exception {
        Class.forName("org.sqlite.JDBC");

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:ventas.db");
             Statement st = conn.createStatement()) {

            st.executeUpdate("DROP TABLE IF EXISTS ventas");
            st.executeUpdate("DROP TABLE IF EXISTS clientes");
            st.executeUpdate("DROP TABLE IF EXISTS secretos_demo");

            st.executeUpdate("""
                CREATE TABLE clientes (
                    id INTEGER PRIMARY KEY,
                    nombre TEXT,
                    ciudad TEXT
                )
            """);

            st.executeUpdate("""
                CREATE TABLE ventas (
                    id INTEGER PRIMARY KEY,
                    cliente_id INTEGER,
                    producto TEXT,
                    monto REAL,
                    fecha TEXT
                )
            """);

            // Tabla "sensible" ficticia solo para que el payload de ataque
            // tenga algo visible que filtrar/borrar, sin usar datos reales.
            st.executeUpdate("""
                CREATE TABLE secretos_demo (
                    clave TEXT,
                    valor TEXT
                )
            """);
            st.executeUpdate("INSERT INTO secretos_demo VALUES ('API_KEY_DEMO','sk-demo-1234-no-es-real')");

            st.executeUpdate("INSERT INTO clientes VALUES (1,'Laura Gomez','Bogota')");
            st.executeUpdate("INSERT INTO clientes VALUES (2,'Andres Pardo','Medellin')");
            st.executeUpdate("INSERT INTO clientes VALUES (3,'Camila Rojas','Cali')");
            st.executeUpdate("INSERT INTO clientes VALUES (4,'Diego Salazar','Bogota')");

            st.executeUpdate("INSERT INTO ventas VALUES (1,1,'Laptop',2500000,'2026-08-01')");
            st.executeUpdate("INSERT INTO ventas VALUES (2,1,'Mouse',60000,'2026-08-02')");
            st.executeUpdate("INSERT INTO ventas VALUES (3,2,'Monitor',900000,'2026-08-03')");
            st.executeUpdate("INSERT INTO ventas VALUES (4,3,'Teclado',150000,'2026-08-05')");
            st.executeUpdate("INSERT INTO ventas VALUES (5,4,'Laptop',2600000,'2026-08-06')");
            st.executeUpdate("INSERT INTO ventas VALUES (6,2,'Laptop',2450000,'2026-08-09')");

            System.out.println("ventas.db creada con datos de ejemplo.");
        }
    }
}
