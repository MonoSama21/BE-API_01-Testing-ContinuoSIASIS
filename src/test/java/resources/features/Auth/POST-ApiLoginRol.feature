@POST-ApiLoginRol
Feature: Login de usuario directivo - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"

# 1. 🔵 Smoke
@contract @smoke @post @test1
Scenario: Validar que el servicio de login responde correctamente
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

# 2. 🔵 Happy Path
@contract @happy-path @post @test2
Scenario Outline: Validar que el servicio de login permite acceder por el <description>
    Given path "api/login/" + route
    And request 
    """
    {
        "Nombre_Usuario": "<usuario>",
        "Contraseña": "<contrasena>"
    }
    """
    When method POST
    Then status 200 
    Examples: 
        | route                      | usuario               | contrasena | description                                        |
        | directivo                  | director.asuncion8    | 15430124   | rol de directivo                                   |
        | profesor-primaria          | marisol_godoy_1537    | 15378317   | rol de profesor de primaria                        |
        | auxiliar                   | brigida_gonzales_1535 | 15357278   | rol de auxiliar                                    |
        | profesor-tutor-secundaria  | david_apolinario_1537 | 15371028   | rol de profesor-tutor secundaria (CASO NO TUTOR)   |
        | profesor-tutor-secundaria  | daniel_sanchez_1542   | 15420745   | rol de personal tutor secundaria (CASO SI TUTOR)   |
        | personal-administrativo    | jose_centeno_4180     | 41809910   | rol de personal personal administrativo            |


# 3. 🧩 Schema Validation

@contract @smoke @post @test3
Scenario Outline: Validar que el servicio de login devuelve una respuesta correcta cuando se accede por el <description>
    Given path "api/login/" + route
    And request 
    """
    {
        "Nombre_Usuario": "<usuario>",
        "Contraseña": "<contrasena>"
    }
    """
    When method POST
    Then status 200 
    And match response ==
    """
    {
    "success": "#boolean",
    "message": "#string",
    "data": {
        "Apellidos": "#string",
        "Nombres": "#string",
        "Rol": "#string",
        "token": "#string",
        "Google_Drive_Foto_ID": "#string",
        "Genero": "#string"
    }
    }
    """

    Examples: 
        | route                      | usuario               | contrasena | description                                        |
        | directivo                  | director.asuncion8    | 15430124   | rol de directivo                                   |
        | profesor-primaria          | marisol_godoy_1537    | 15378317   | rol de profesor de primaria                        |
        | auxiliar                   | brigida_gonzales_1535 | 15357278   | rol de auxiliar                                    |
        | profesor-tutor-secundaria  | david_apolinario_1537 | 15371028   | rol de profesor-tutor secundaria (CASO NO TUTOR)   |
        | profesor-tutor-secundaria  | daniel_sanchez_1542   | 15420745   | rol de personal tutor secundaria (CASO SI TUTOR)   |
        | personal-administrativo    | jose_centeno_4180     | 41809910   | rol de personal personal administrativo            |

# 4. 📋 Headers Validation
@contract @headers @post
Scenario: Validar headers obligatorios y de respuesta
    Given path "api/login/directivo"
    And header Content-Type = "application/json"
    And request { "Nombre_Usuario": "director.asuncion8", "Contraseña": "15430124" }
    When method POST
    Then status 200
    And match responseHeaders['Content-Type'][0] contains "application/json"



# 5. ❌ Error Handling 🏷️ Field Validation
@contract @error-handling @post @vaya
Scenario Outline: Validar manejo de errores del endpoint
    Given path "api/login/directivo"
    And request <body>
    When method POST
    Then status 400
    And match response.success == false
    * match response.message == "El nombre de usuario y la contraseña son obligatorios"
    * match response.errorType == "MISSING_PARAMETERS"

Examples:
    | body                                                        |
    | {}                                                          |
    | { "Nombre_Usuario": "" , "Contraseña": "123" }              | 
    | { "Nombre_Usuario": "test" , "Contraseña": "" }             | 
    | { "Nombre_Usuario": "", "Contraseña": "" }                  |


@contract @error-handling @post @vaya2
Scenario Outline: Validar manejo de errores del endpoint
    Given path "api/login/directivo"
    And request <body>
    When method POST
    Then status 401
    And match response.success == false
    * match response.message == "Credenciales inválidas"
    * match response.errorType == "INVALID_CREDENTIALS"
    
    Examples: 
        | body                                                        | 
        | { "Nombre_Usuario": "noExiste" , "Contraseña": "123" }      | 
        | { "Nombre_Usuario": "director.asuncion8", "Contraseña": "x"}| 



# 7. 🔠 Data Types  #ESTA BIEN QUE FALLE
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
