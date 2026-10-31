# Análisis costo-beneficio: Mini Security Gateway de salida para LLMs

Caso de estudio ficticio para el seminario de Fundamentos de Seguridad de la Información
(OWASP LLM05: Improper Output Handling).

Los costos de implementación y de la API salen de fuentes públicas ([sección 9](#9-fuentes)). El
tamaño de la empresa, el impacto de cada incidente y las probabilidades son **supuestos del caso**.
Cifras en pesos colombianos (COP), con la TRM de **3.174,67 COP por dólar** (17–19 de octubre de 2026).

## Resumen

| Indicador | Valor |
|---|---|
| Dueña del asistente y del gateway | **TecnoVentas** |
| Lo que cobramos el año 1 | **50.000.000 COP** (≈ USD 15.750) |
| Lo que cobramos los años siguientes | **30.800.000 COP** |
| Ahorro anual para TecnoVentas (pérdidas esperadas evitadas) | 102.000.000 COP |
| Retorno de la inversión en seguridad (ROSI), año 1 | ≈ 104 % |
| Recuperación de la inversión | ≈ 5,9 meses |
| Costo del LLM por tokens (aparte) | ≈ 7.500 a 151.000 COP al mes |

## 1. La empresa

**TecnoVentas S.A.S.** es una comercializadora de tecnología con sede en Bogotá y clientes en siete
ciudades de Colombia. Vende laptops, celulares, monitores, tablets y periféricos.

- 45 empleados, de los cuales 12 son asesores comerciales.
- Ventas promedio: 25.000.000 COP diarios (unos 6.000 millones al año).
- Base de datos de clientes y ventas con la misma estructura del MVP: tablas `clientes`, `ventas` y
  una tabla con credenciales internas (en el MVP, `secretos_demo`).

La empresa es inventada: el repositorio solo trae los datos de prueba. Se eligió para que coincida con
esa base de datos.

## 2. El problema

Para agilizar el trabajo, TecnoVentas implementó un asistente con un LLM: los asesores escriben en
lenguaje natural ("¿cuánto vendimos por cliente en septiembre?") y el asistente genera la consulta SQL
y la ejecuta directamente. El equipo de TI también usa un asistente que traduce peticiones a comandos
del servidor.

Es el mismo patrón del **CVE-2024-5565 (Vanna.AI)**: la salida del LLM se ejecuta sin validar y con
todos los permisos de la aplicación. Una petición maliciosa, un prompt injection o un simple error del
modelo puede borrar las ventas, filtrar datos personales y credenciales, o comprometer el servidor.

## 3. La solución propuesta

Implementar el **mini security gateway de salida** del MVP como una capa entre el LLM y la ejecución:

1. **Validación de la salida con allow-list:** solo consultas `SELECT` sobre tablas autorizadas y solo
   comandos permitidos, sin encadenamientos (`SqlValidator`, `CommandValidator`).
2. **Mínimo privilegio:** base de datos en solo lectura y comandos sin intérprete de shell.
3. Para producción se añaden alertas y pruebas de seguridad.

## 3.1 Quién se queda con qué

**TecnoVentas es la dueña.** Nosotros somos el proveedor que lo implementa y lo mantiene.

| Elemento | Dueño | Qué pasa si termina el contrato |
|---|---|---|
| Asistente con LLM, sus datos y sus registros | TecnoVentas | Sigue siendo suyo |
| Código del gateway y sus reglas | TecnoVentas: se le entrega al final del proyecto | Lo conserva y su equipo de TI puede mantenerlo |
| Modelo de lenguaje (LLM) | Anthropic: TecnoVentas tiene la cuenta y paga los tokens directamente | No depende de nosotros |
| Nuestro trabajo | Desarrollo, pentest, capacitación y mantenimiento anual | Deja de cobrarse |

Así TecnoVentas no queda amarrada a nosotros: paga por un servicio, no por el derecho a usar lo que ya
compró.

## 4. Costo de implementación y lo que cobramos

| Concepto | Supuesto y fuente | Costo (COP) |
|---|---|---|
| Desarrollo e integración | 160 h × ≈100.000 COP/h. La hora sale de un salario de 12 M/mes para un backend senior en Bogotá (rango 11–18 M según JobRise 2026), × 1,5 de carga prestacional (supuesto), ÷ 176 h al mes | 16.000.000 |
| Pruebas de seguridad (pentest) | Pentest de una aplicación web sencilla: desde USD 5.000 (Astra, 2026) × TRM | 16.000.000 |
| Infraestructura y logs | Servidor pequeño en la nube ≈ USD 20/mes (Amazon Lightsail tiene planes desde USD 5–7/mes) × 12 | 760.000 |
| Mantenimiento | 10 h/mes × 100.000 × 12 (supuesto) | 12.000.000 |
| Capacitación al equipo | Taller interno de uso seguro de LLMs (supuesto) | 2.000.000 |
| **Total año 1** | | **46.760.000** (≈ USD 14.700) |
| **Total años siguientes** | Infraestructura, mantenimiento y un pentest de control al año | **28.760.000** |

**Por qué baja el segundo año:** 18 M solo se pagan una vez, y lo demás se repite todos los años.
Sobre ese costo cobramos un margen del **7 %**.

| Concepto | Año 1 (COP) | Años siguientes (COP) | ¿Se repite? |
|---|---|---|---|
| Desarrollo e integración | 16.000.000 | 0 | No, el gateway ya queda construido |
| Capacitación al equipo | 2.000.000 | 0 | No, el equipo ya queda capacitado |
| Pentest | 16.000.000 | 16.000.000 | Sí, las amenazas cambian: una prueba al año |
| Mantenimiento | 12.000.000 | 12.000.000 | Sí, actualizar reglas y atender incidentes |
| Infraestructura y logs | 760.000 | 760.000 | Sí, el servidor se paga cada mes |
| **Costo** | **46.760.000** | **28.760.000** | |
| Margen (≈ 7 %) | 3.240.000 | 2.040.000 | |
| **Lo que cobramos** | **50.000.000** | **30.800.000** | |

El cobro baja 19,2 M: los 18 M que no se repiten y 1,2 M de margen sobre ellos.

**Por qué cobramos 50 M el primer año:** son los 46,8 M que cuesta el proyecto más nuestro margen, y
el primer año es el más caro porque incluye construir el gateway y capacitar al equipo. Ese margen es
lo que nos deja sostener el servicio. Con él, TecnoVentas sigue recuperando lo invertido en menos de
seis meses.

## 4.1 Costo del LLM por tokens

El gateway no consume tokens: valida la salida con reglas en Java. Los tokens los gasta el asistente
con LLM, que TecnoVentas pagaría con o sin gateway; por eso este costo se muestra aparte y no entra en
el retorno de la inversión.

Precios oficiales de Anthropic por millón de tokens:

| Modelo | Entrada | Salida |
|---|---|---|
| Claude Sonnet 5.5 (el modelo por defecto en `LlmClient.java`) | USD 2 | USD 10 |
| Claude Haiku 5.5 | USD 0,10 | USD 0,50 |

Leer instrucciones repetidas desde la caché cuesta USD 0,10 por millón en Sonnet 5.5.

**Supuestos de uso:** 12 asesores × 40 consultas al día × 22 días = **10.560 consultas al mes**. Cada
consulta lleva unos 1.500 tokens de entrada (instrucciones, esquema de la base de datos y la pregunta)
y devuelve unos 150 tokens (la consulta SQL). El prompt del MVP es más corto; estos valores
corresponden a una versión de producción con más tablas.

Ejemplo de cálculo con Sonnet 5.5: (1.500 × USD 2 + 150 × USD 10) ÷ 1.000.000 = USD 0,0045 por consulta.

| Modelo | Costo por consulta | Costo al mes | Costo al año |
|---|---|---|---|
| Sonnet 5.5 | USD 0,0045 | USD 47,5 ≈ 151.000 COP | ≈ 1.810.000 COP |
| Sonnet 5.5 con caché del prompt | USD 0,0018 | ≈ 62.000 COP | ≈ 740.000 COP |
| Haiku 5.5 | USD 0,0002 | USD 2,4 ≈ 7.500 COP | ≈ 90.000 COP |

En modo simulación (sin API key) el MVP no tiene costo de tokens.

## 5. Pérdidas esperadas sin el gateway

Se usa el modelo clásico de riesgo:
**pérdida anual esperada (ALE) = impacto por incidente (SLE) × probabilidad anual (ARO)**.

| Escenario (ataque del MVP) | Impacto por incidente | Probabilidad anual | Pérdida anual esperada |
|---|---|---|---|
| Borrado de la BD de ventas (`DELETE`) | 60.000.000: 2 días de operación detenida (50 M) + recuperación (10 M) | 50 % | 30.000.000 |
| Fuga de datos de clientes y credenciales | 250.000.000: sanción de la SIC (150 M) + forense y notificación (40 M) + clientes perdidos (60 M) | 20 % | 50.000.000 |
| Compromiso del servidor (concatenación, reverse shell) | 400.000.000: ransomware, operación detenida y recuperación | 10 % | 40.000.000 |
| **Total sin gateway** | | | **120.000.000** |

**Referencias para el impacto:** la Ley 1581 de 2012 permite a la SIC multar hasta 2.000 salarios
mínimos, unos **3.494 millones de COP** con el salario mínimo de 2026 (1.746.882 COP). Los 150 M del
escenario son una multa moderada, cerca del 4 % del máximo. Como referencia de escala, IBM calcula que
una filtración de datos en Latinoamérica costó en promedio **USD 2,51 millones** (≈ 7.968 M COP) en
2025; ese promedio incluye empresas grandes, así que para una empresa del tamaño de TecnoVentas se usó
un valor mucho menor. Las probabilidades anuales son supuestos del caso.

## 6. Ahorro y retorno

Se asume que el gateway reduce el riesgo en un 85 %, un valor conservador: en el benchmark bloquea el
98,8 % de los ataques (`MVP.md`, §8), pero esos casos los escribimos nosotros. La segunda barrera (solo
lectura y sin shell) contiene lo que se escape del validador.

| Indicador | Valor |
|---|---|
| Pérdida esperada sin gateway | 120.000.000 COP/año |
| Pérdida residual con gateway (15 %) | 18.000.000 COP/año |
| **Ahorro anual (reducción de riesgo)** | **102.000.000 COP** |
| Lo que paga TecnoVentas, año 1 | 50.000.000 COP |
| Lo que paga TecnoVentas, años siguientes | 30.800.000 COP |
| **Retorno de la inversión en seguridad (ROSI), año 1** | (102 − 50) / 50 ≈ **104 %** |
| ROSI años siguientes | (102 − 30,8) / 30,8 ≈ **231 %** |
| **Recuperación de la inversión** | 50 ÷ 102 × 12 ≈ **5,9 meses** |

Por cada peso invertido el primer año, TecnoVentas evita unos 2 pesos de pérdidas esperadas; desde el
segundo año, unos 3,3.

## 7. Conclusión

El gateway es una inversión pequeña frente al riesgo: cuesta menos de la mitad de lo que se espera
perder en un solo año sin él, y se paga en unos seis meses. Además protege beneficios difíciles de
cuantificar: la confianza de los clientes, el cumplimiento de la Ley 1581 y la posibilidad de seguir
usando LLMs de forma segura.

## 8. Limitaciones del análisis

- El tamaño de la empresa, los impactos y las probabilidades son supuestos para un caso ficticio; en
  una empresa real se calculan con sus ventas, su inventario de datos y su historial de incidentes.
- Las probabilidades son estimaciones subjetivas.
- El 85 % de reducción supone un gateway bien mantenido; los validadores por reglas no son infalibles.
- Los precios de la API y la TRM cambian; están tomados a octubre de 2026.

## 9. Fuentes

- [Precios de la API de Anthropic](https://platform.claude.com/docs/en/about-claude/pricing): precio
  por millón de tokens de Sonnet 5.5 y Haiku 5.5, caché y descuento por lotes.
- [Salario de un Backend Developer en Bogotá 2026 (JobRise)](https://jobrise.io/es/blog/salario-backend-developer-bogota-2026/):
  rangos mensuales por nivel; el artículo no cita metodología.
- [Salario mínimo 2026 (Consultorsalud)](https://consultorsalud.com/salario-minimo-vital-2026-en-colombia-llega-a-2-millones-ultima-hora/):
  SMMLV de 1.746.882 COP.
- [TRM del 17 al 19 de octubre de 2026 (Portafolio)](https://www.portafolio.co/economia/finanzas/precio-del-dolar-hoy-en-colombia-asi-cotiza-la-divisa-este-lunes-19-de-octubre-504692):
  3.174,67 COP por dólar.
- [Costo de un pentest en 2026 (Astra)](https://www.getastra.com/blog/penetration-testing/cost/): una
  aplicación web sencilla desde unos USD 5.000.
- [Precios de Amazon Lightsail (CloudZero)](https://www.cloudzero.com/blog/amazon-lightsail-pricing/):
  servidores desde USD 5–7 al mes.
- [Multas por datos personales, Ley 1581 (Holland & Knight)](https://www.hklaw.com/es/news/intheheadlines/2025/09/venta-de-datos-personales-sin-autorizacion-podria-generar-multas):
  hasta 2.000 SMMLV.
- [Informe IBM 2025 sobre filtraciones en Latinoamérica (La Nota Económica)](https://lanotaeconomica.com.co/movidas-empresarial/ibm-la-seguridad-impulsada-por-ia-y-automatizacion-reduce-los-costos-de-las-filtraciones-de-datos-en-latinoamerica/):
  costo promedio de USD 2,51 millones.
