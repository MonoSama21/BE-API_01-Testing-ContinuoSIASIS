Feature: Login de usuario directivo - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"


# 1. 🔵 Smoke Test
@contract @smoke @post
Scenario: Verificar que el endpoint acepta requests
    Given path "api/login/directivo"
    And request { "Nombre_Usuario": "test", "Contraseña": "123" }
    When method POST
    Then status 400  # No importa si falla, lo importante es que responde


# 2. 🟢 Happy Path (ya lo tienes, lo reestructuro)
@contract @happy-path @post
Scenario: Login exitoso con credenciales válidas
    Given path "api/login/directivo"
    And request
    """
    {
        "Nombre_Usuario": "director.asuncion8",
        "Contraseña": "15430124"
    }
    """
    When method POST
    Then status 200
    And match response == { token: "#string" }


# 3. 🧩 Schema Validation
@contract @schema @post
Scenario: Validar que el response cumple el esquema del contrato
    Given path "api/login/directivo"
    And request
    """
    {
        "Nombre_Usuario": "director.asuncion8",
        "Contraseña": "15430124"
    }
    """
    When method POST
    Then status 200
    And match response ==
    """
    {
        token: "#string"
    }
    """


# 4. 📋 Headers Validation
@contract @headers @post
Scenario: Validar headers obligatorios y de respuesta
    Given path "api/login/directivo"
    And header Content-Type = "application/json"
    And request { "Nombre_Usuario": "director.asuncion8", "Contraseña": "15430124" }
    When method POST
    Then status 200
    And match responseHeaders['Content-Type'][0] contains "application/json"


# 5. ❌ Error Handling
@contract @error-handling @post
Scenario Outline: Validar manejo de errores del endpoint
    Given path "api/login/directivo"
    And request <body>
    When method POST
    Then status <expectedStatus>
    And match response.message == "#string"

Examples:
    | body                                                        | expectedStatus |
    | {}                                                          | 400 |
    | { "Nombre_Usuario": "" , "Contraseña": "123" }              | 400 |
    | { "Nombre_Usuario": "test" , "Contraseña": "" }             | 400 |
    | { "Nombre_Usuario": "noExiste" , "Contraseña": "123" }      | 401 |
    | { "Nombre_Usuario": "director.asuncion8", "Contraseña": "x"}| 401 |


# 6. 🏷️ Field Validation
@contract @fields @post
Scenario: Validar campos obligatorios del request
    Given path "api/login/directivo"
    And request { "Nombre_Usuario": "", "Contraseña": "" }
    When method POST
    Then status 400
    And match response.message contains 'Nombre_Usuario'
    And match response.message contains 'Contraseña'


# 7. 🔠 Data Types
@contract @data-types @post
Scenario Outline: Validar tipos de datos inválidos
    Given path "api/login/directivo"
    And request <body>
    When method POST
    Then status 400

Examples:
    | body |
    | { "Nombre_Usuario": 123, "Contraseña": "123" } |
    | { "Nombre_Usuario": "test", "Contraseña": 123 } |
    | { "Nombre_Usuario": [], "Contraseña": "123" } |
    | { "Nombre_Usuario": "test", "Contraseña": {} } |


# 8. ⚠️ Boundary Testing
@contract @boundary @post
Scenario Outline: Validar valores límite del login
    Given path "api/login/directivo"
    And request
    """
    {
        "Nombre_Usuario": "<username>",
        "Contraseña": "<password>"
    }
    """
    When method POST
    Then status <expectedStatus>

Examples:
    | username | password | expectedStatus |
    | a | 1 | 401 |
    | usuario_muy_largo_mas_de_100_caracteres_____________________________ | 123 | 400 |
    | normalUser | contraseña_muy_larga________________________________________________ | 400 |
    | (empty) | 123 | 400 |
    | test<script> | 123 | 400 |

    # =======================================================================
# 🛡️ SECURITY CONTRACT TESTING — Validación de vulnerabilidades OWASP
# =======================================================================

# 9. 🚨 SQL Injection Attempts
@contract @security @sql-injection @post
Scenario Outline: Intentos de SQL Injection deben ser rechazados
    Given path "api/login/directivo"
    And request
    """
    {
        "Nombre_Usuario": "<payload>",
        "Contraseña": "<payload>"
    }
    """
    When method POST
    Then status 400
    And match response.message contains "invalid"

Examples:
    | payload |
    | ' OR '1'='1 |
    | '; DROP TABLE usuarios; -- |
    | ' OR 1=1 -- |
    | ' UNION SELECT NULL, NULL -- |
    | admin'/* |


# 10. 🧨 XSS Injection
@contract @security @xss @post
Scenario Outline: Intentos de Cross-Site Scripting deben ser bloqueados
    Given path "api/login/directivo"
    And request
    """
    {
        "Nombre_Usuario": "<xss>",
        "Contraseña": "<xss>"
    }
    """
    When method POST
    Then status 400

Examples:
    | xss |
    | <script>alert(1)</script> |
    | <img src=x onerror=alert('XSS')> |
    | javascript:alert('XSS') |
    | <svg/onload=alert(1)> |
    | <iframe src='javascript:alert(1)'></iframe> |


# 11. 🔐 Login Brute Force Simulation (Protección anti fuerza bruta)
@contract @security @bruteforce @post
Scenario: Intentos múltiples fallidos deben responder 401 sin cambios en el contrato
    * def body = { Nombre_Usuario: "user.fake", Contraseña: "incorrecta" }

    # tres intentos fallidos
    Given path "api/login/directivo"
    And request body
    When method POST
    Then status 401

    Given path "api/login/directivo"
    And request body
    When method POST
    Then status 401

    Given path "api/login/directivo"
    And request body
    When method POST
    Then status 401


# 12. 🧱 Payload Tampering (JSON Manipulation)
@contract @security @json-tamper @post
Scenario Outline: Enviar tipos de datos inesperados
    Given path "api/login/directivo"
    And request <payload>
    When method POST
    Then status 400

Examples:
    | payload |
    | "null" |
    | "[]" |
    | "\"string-maliciosa\"" |
    | "{ \"Nombre_Usuario\": {\"hack\": 1}, \"Contraseña\": \"123\" }" |
    | "{ \"Nombre_Usuario\": true, \"Contraseña\": false }" |


# 13. 📦 Oversized Payload (DoS básico)
@contract @security @dos-size @post
Scenario: Payload demasiado grande debe ser rechazado
    * def longText = 'a'.repeat(50000)
    Given path "api/login/directivo"
    And request
    """
    {
        "Nombre_Usuario": "#(longText)",
        "Contraseña": "#(longText)"
    }
    """
    When method POST
    Then status 400


# 14. 🌐 HTTP Header Injection
@contract @security @header-injection @post
Scenario Outline: Cabeceras manipuladas deben ser rechazadas o ignoradas
    Given path "api/login/directivo"
    And header Authorization = <inject>
    And request { "Nombre_Usuario": "user", "Contraseña": "123" }
    When method POST
    Then status 400

Examples:
    | inject |
    | "Bearer null\r\nInjectedHeader: evil" |
    | "\nX-Hacked: 1" |
    | "Bearer <script>hack()</script>" |


# 15. 🧵 Unicode / Encoding Attacks
@contract @security @encoding @post
Scenario Outline: Caracteres especiales maliciosos no deben romper el API
    Given path "api/login/directivo"
    And request
    """
    {
        "Nombre_Usuario": <text>,
        "Contraseña": <text>
    }
    """
    When method POST
    Then status 400

Examples:
    | text |
    | "😈😈😈" |
    | "áéíóúñ漢字" |
    | "%00%00%00" |
    | "\\u0000\\u0001\\u0002" |
    | "־׆﷽" |
