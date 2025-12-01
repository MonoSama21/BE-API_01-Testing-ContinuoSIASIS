@POST-ApiLoginRol
Feature: Login de usuario directivo - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"
    * def requestExitoso = read("classpath:resources/request/POST-ApiLoginRol/request.json")

# 1. 🔵 Smoke
@contract @smoke @post @test1
Scenario: Validar que el servicio de login responde correctamente
    Given path "api/login/directivo"
    And request requestExitoso
    When method POST
    Then status 200 

# 2. 🔵 Happy Path
@contract @happy-path @post @test2
Scenario Outline: Validar que el servicio de login permite acceder por el <description>
    Given path "api/login/" + route
    And request requestExitoso
    * set requestExitoso.Nombre_Usuario = usuario
    * set requestExitoso.Contraseña = contrasena
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
    And request requestExitoso
    * set requestExitoso.Nombre_Usuario = usuario
    * set requestExitoso.Contraseña = contrasena
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
    And request requestExitoso
    When method POST
    Then status 200
    And match responseHeaders['Content-Type'][0] contains "application/json"



# 5. ❌ Error Handling 🏷️ Field Validation
@contract @error-handling @post 
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


@contract @error-handling @post 
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

# 6. 🔠 Data Types  #REPORTAR COMO BUG
@contract @data-types @post
Scenario Outline: Validar tipos de datos inválidos
    Given path "api/login/directivo"
    And request <body>
    When method POST
    Then status 400

    Examples:
        | body |
        | { "Nombre_Usuario": 123, "Contraseña": "123" }  |
        | { "Nombre_Usuario": "test", "Contraseña": 123 } |
        | { "Nombre_Usuario": [], "Contraseña": "123" }   |
        | { "Nombre_Usuario": "test", "Contraseña": {} }  |

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
    And match response.error == "Petición bloqueada por seguridad"
    * match response.message == "Se ha detectado contenido potencialmente malicioso en la petición"
    * match response.code == "SQL_INJECTION_DETECTED"
    * match response.timestamp == "#string"

    Examples:
        | payload |
        | ' OR '1'='1                  |
        | '; DROP TABLE usuarios; --   |
        | ' OR 1=1 --                  |
        | ' UNION SELECT NULL, NULL -- |


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
    Then status 401
    And match response.success == false
    * match response.message == "Credenciales inválidas"
    * match response.errorType == "INVALID_CREDENTIALS"

    Examples:
        | xss |
        | <script>alert(1)</script>                   |
        | <img src=x onerror=alert('XSS')>            |
        | javascript:alert('XSS')                     |
        | <svg/onload=alert(1)>                       |
        | <iframe src='javascript:alert(1)'></iframe> |


# 12. 🧱 Payload Tampering (JSON Manipulation)
@contract @security @json-tamper @post
Scenario Outline: Enviar tipos de datos inesperados
    Given path "api/login/directivo"
    And request <payload>
    When method POST
    Then status 400

    Examples:
        | payload |
        | "null"                                                |
        | "[]"                                                  |
        | "\"string-maliciosa\""                                | 
        | "{ \"Nombre_Usuario\": true, \"Contraseña\": false }" |


# 14. 🌐 HTTP Header Injection  #ES BUG
@contract @security @header-injection @post
Scenario Outline: Cabeceras manipuladas deben ser rechazadas o ignoradas
    Given path "api/login/directivo"
    And header Authorization = <inject>
    And request requestExitoso
    When method POST
    Then status 400

    Examples:
        | inject |
        | "Bearer null\r\nInjectedHeader: evil" |
        | "\nX-Hacked: 1"                       |
        | "Bearer <script>hack()</script>"      |
