package com.fdsi.mvp;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

/**
 * Crea ventas.db con datos de ejemplo. Correr una sola vez:
 *   mvn compile exec:java -Dexec.mainClass=com.fdsi.mvp.DbInit
 * o, con el jar ya empaquetado:
 *   java -cp target/mvp-llm-output-handling-1.0.0-jar-with-dependencies.jar com.fdsi.mvp.DbInit
 * Tambien se puede restaurar desde la interfaz web (boton "Restaurar base de datos").
 */
public class DbInit {

    public static void main(String[] args) throws Exception {
        crear();
        System.out.println("ventas.db creada con datos de ejemplo.");
    }

    /** Borra y vuelve a crear las tablas con los datos de ejemplo. */
    public static void crear() throws Exception {
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
            st.executeUpdate("INSERT INTO secretos_demo VALUES ('DB_PASSWORD_DEMO','contrasena-ficticia-demo')");

            st.executeUpdate("""
                INSERT INTO clientes VALUES
                    (1,'Laura Gomez','Bogota'),
                    (2,'Andres Pardo','Medellin'),
                    (3,'Camila Rojas','Cali'),
                    (4,'Diego Salazar','Bogota'),
                    (5,'Valentina Ruiz','Barranquilla'),
                    (6,'Santiago Mejia','Medellin'),
                    (7,'Mariana Lopez','Bucaramanga'),
                    (8,'Felipe Herrera','Cartagena'),
                    (9,'Daniela Castro','Bogota'),
                    (10,'Juan Ortiz','Cali')
            """);

            st.executeUpdate("""
                INSERT INTO ventas VALUES
                    (1,1,'Laptop',2500000,'2026-08-01'),
                    (2,1,'Mouse',60000,'2026-08-02'),
                    (3,2,'Monitor',900000,'2026-08-03'),
                    (4,3,'Teclado',150000,'2026-08-05'),
                    (5,4,'Laptop',2600000,'2026-08-06'),
                    (6,2,'Laptop',2450000,'2026-08-09'),
                    (7,5,'Impresora',780000,'2026-08-11'),
                    (8,6,'Audifonos',220000,'2026-08-12'),
                    (9,7,'Tablet',1350000,'2026-08-14'),
                    (10,8,'Celular',1900000,'2026-08-15'),
                    (11,9,'Monitor',950000,'2026-08-17'),
                    (12,10,'Teclado',175000,'2026-08-18'),
                    (13,3,'Mouse',65000,'2026-08-20'),
                    (14,5,'Laptop',2700000,'2026-08-22'),
                    (15,6,'Celular',1850000,'2026-08-24'),
                    (16,4,'Disco SSD',420000,'2026-08-26'),
                    (17,7,'Audifonos',240000,'2026-08-28'),
                    (18,8,'Tablet',1400000,'2026-08-30'),
                    (19,9,'Impresora',810000,'2026-09-01'),
                    (20,10,'Laptop',2550000,'2026-09-03'),
                    (21,1,'Disco SSD',390000,'2026-09-05'),
                    (22,2,'Celular',1950000,'2026-09-07'),
                    (23,3,'Monitor',920000,'2026-09-09'),
                    (24,6,'Mouse',70000,'2026-09-11'),
                    (25,9,'Laptop',2650000,'2026-09-13'),
                    (26,5,'Teclado',160000,'2026-09-15'),
                    (27,7,'Celular',1880000,'2026-09-17'),
                    (28,8,'Disco SSD',410000,'2026-09-19'),
                    (29,10,'Audifonos',230000,'2026-09-21'),
                    (30,4,'Tablet',1320000,'2026-09-23')
            """);
        }
    }
}
