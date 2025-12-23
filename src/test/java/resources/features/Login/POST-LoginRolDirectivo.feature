@postLoginRolDirectivo @login @dailyTests
Feature: Login de usuario directivo - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"
    * def requestExitoso = read("classpath:resources/functional/request/Auth/requestDirectivo.json")
    * def schemas = read('classpath:resources/functional/schema/LoginSuccessResponse.json')

# =======================================================================
# 1. 🔵 SMOKE Y HAPPY PATH 
# =======================================================================
@contract @smoke @post @happy-path @tokenDirectivo
Scenario: Validar que el servicio de login responde correctamente para el rol directivo
    Given path "api/login/directivo"
    And request requestExitoso
    When method POST
    Then status 200
    * def token = response.data.token 

# =======================================================================
# 2. 🧩 SCHEMA VALIDATION
# =======================================================================
@contract @schema @post 
Scenario: Validar que el servicio de login devuelve una respuesta correcta cuando se accede por el rol directivo
    Given path "api/login/directivo"
    And request requestExitoso
    When method POST
    Then status 200
    And match response == schemas['200']

# =======================================================================
# 3. 📋 HEADERS VALIDATION
# =======================================================================
@contract @headers @post
Scenario: Validar headers de respuesta al acceder por el rol directivo
    Given path "api/login/directivo"
    And request requestExitoso
    When method POST
    Then status 200
    And match responseHeaders['Content-Type'][0] contains "application/json"

# =======================================================================
# 4. ❌ ERROR HANDLING 🏷️ FIELD VALIDATION
# =======================================================================
@contract @error-handling @post
Scenario Outline: Validar <descripcion> con rol directivo
    Given path "api/login/directivo"
    And request <body>
    When method POST
    Then status 400
    And match response == schemas['400']
    And match response.success == false
    * match response.message == "El nombre de usuario y la contraseña son obligatorios"
    * match response.errorType == "MISSING_PARAMETERS"

    Examples:
        | descripcion                                                           | body                                                |
        | ausencia de campos obligatorios con body vacío                        | {}                                                  |
        | ausencia de campo nombre de usuario con valor vacío                   | { "Nombre_Usuario": "" , "Contraseña": "123" }      |
        | ausencia de campo contraseña con valor vacío                          | { "Nombre_Usuario": "test" , "Contraseña": "" }     |
        | ausencia de ambos campos obligatorios con valores vacíos              | { "Nombre_Usuario": "", "Contraseña": "" }          |

@contract @error-handling @post
Scenario Outline: Validar <descripcion> con rol directivo
    Given path "api/login/directivo"
    And request <body>
    When method POST
    Then status 401
    And match response == schemas['401']
    And match response.success == false
    * match response.message == "Credenciales inválidas"
    * match response.errorType == "INVALID_CREDENTIALS"
    
    Examples: 
        | descripcion                                                           | body                                                        | 
        | que no se permite el acceso con usuario inexistente                   | { "Nombre_Usuario": "noExiste" , "Contraseña": "123" }      | 
        | que no se permite el acceso con contraseña incorrecta                 | { "Nombre_Usuario": "director.asuncion8", "Contraseña": "x"}| 

# =======================================================================
# 5. 🔠 DATA TYPES (REPORTAR COMO BUG)
# =======================================================================
@contract @data-types @post @bug
Scenario Outline: Validar <descripcion> con rol directivo
    Given path "api/login/directivo"
    And request requestExitoso
    * set requestExitoso.Nombre_Usuario = usuario
    * set requestExitoso.Contraseña = contrasena
    When method POST
    Then status 400
    And match response == schemas['400']

    Examples:
        | descripcion                                                      | usuario               | contrasena       |
        | tipo de dato inválido número en campo usuario                   | 123                   | "12345678P"      |
        | tipo de dato inválido número en campo contraseña                | "director.asuncion8"  | 123              |
        | tipo de dato inválido array en campo usuario                    | []                    | "12345678P"      |
        | tipo de dato inválido objeto en campo contraseña                | "director.asuncion8"  | {}               |

# =======================================================================
# 6. 🛡️ SECURITY CONTRACT TESTING — Validación de vulnerabilidades OWASP
# =======================================================================

# 🧨 XSS Injection
@contract @security @xss @post
Scenario Outline: Validar <descripcion> con rol directivo
    Given path "api/login/directivo"
    And request requestExitoso
    * set requestExitoso.Nombre_Usuario = xss
    * set requestExitoso.Contraseña = xss
    When method POST
    Then status 401
    And match response == schemas['401']
    And match response.success == false
    * match response.message == "Credenciales inválidas"
    * match response.errorType == "INVALID_CREDENTIALS"

    Examples:
        | descripcion                                                      | xss                                         |
        | intento de XSS con script tag                                    | <script>alert(1)</script>                   |
        | intento de XSS con img tag y onerror                             | <img src=x onerror=alert('XSS')>            |
        | intento de XSS con javascript protocol                           | javascript:alert('XSS')                     |
        | intento de XSS con svg tag y onload                              | <svg/onload=alert(1)>                       |
        | intento de XSS con iframe tag y javascript protocol              | <iframe src='javascript:alert(1)'></iframe> |


# 🧱 Payload Tampering (JSON Manipulation)
@contract @security @json-tamper @post
Scenario Outline: Validar <descripcion> con rol directivo
    Given path "api/login/directivo"
    And request <payload>
    When method POST
    Then status 400
    And match response == schemas['400']

    Examples:
        | descripcion                                                      | payload                                               |
        | payload tampering con valor null                                 | "null"                                                |
        | payload tampering con array vacío                                | "[]"                                                  |
        | payload tampering con string maliciosa                           | "\"string-maliciosa\""                                |
        | payload tampering con booleanos en campos de credenciales        | "{ \"Nombre_Usuario\": true, \"Contraseña\": false }" |


# 🌐 HTTP Header Injection  #ES BUG
@contract @security @header-injection @post @uos
Scenario Outline: Validar inyección en cabeceras HTTP al acceder por el rol directivo <descripcion>
    Given path "api/login/directivo"
    And header Authorization = <inject>
    And request requestExitoso
    When method POST
    Then status 400
    And match response == schemas['400']

    Examples:
        | descripcion                                                          | inject                                |
        | Header Injection - bearer con salto de línea e inyección maliciosa   | "Bearer null\r\nInjectedHeader: evil" |
        | Header Injection - salto de línea con cabecera X-Hacked              | "\nX-Hacked: 1"                       |
        | Header Injection - script XSS en Authorization header                | "Bearer <script>hack()</script>"      |


