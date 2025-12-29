@misDatosAuxiliar @dailyTests 
Feature: Retorna los datos personal del rol Auxiliar - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"
    * def result = call read('classpath:resources/features/Login/POST-LoginRolAuxiliar.feature@tokenAuxiliar')
    * def auxiliarToken = result.token
    * def schemas = read('classpath:resources/functional/schema/MisDatosResponse.json') 

# =======================================================================
# 1. 🔵 SMOKE 
# =======================================================================
@contract @smoke @get @1
Scenario: Validar que el servicio de Mis Datos funciona para el rol Auxiliar
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + auxiliarToken
    When method GET
    Then status 200

# =======================================================================
# 2. 🔵 HAPPY PATH
# =======================================================================
@contract @happy-path @get
Scenario: Validar que el servicio de Mis Datos retorna datos completos para el rol Auxiliar
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + auxiliarToken
    When method GET
    Then status 200
    And match response.success == true
    And match response.data.Id_Auxiliar == '#present'
    And match response.data.Nombres == '#string'
    And match response.data.Apellidos == '#string'
    And match response.data.Nombre_Usuario == '#string'
    And match response.data.Correo_Electronico == '#string'

# =======================================================================
# 3. 🔵 SCHEMA VALIDATION
# =======================================================================
@contract @schema @get
Scenario: GET mis-datos - Response schema es correcto para Auxiliar
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + auxiliarToken
    When method GET
    Then status 200
    And match response == schemas['200']

# =======================================================================
# 4. 🔵 HEADERS VALIDATION
# =======================================================================
@contract @headers @get
Scenario: GET mis-datos - Headers de request y response
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + auxiliarToken
    And header Content-Type = 'application/json'
    When method GET
    Then status 200
    And match responseHeaders['Content-Type'][0] contains 'application/json'

# =======================================================================
# 5. 🔵 ERROR HANDLING
# =======================================================================

@contract @error-handling @get @sinpermisos
Scenario: GET mis-datos - Error 401 Token inválido
    Given path "/api/mis-datos"
    # Usar token de otro rol para simular falta de permisos si aplica
    And header Authorization = 'Bearer tokenConPermisosInsuficientes'
    When method GET
    Then status 401
    And match response == schemas['401']

@contract @error-handling @get
Scenario: GET mis-datos - Error 404 Recurso no encontrado
    Given path "/api/mis-datos-inexistente"
    And header Authorization = 'Bearer ' + auxiliarToken
    When method GET
    Then status 404
    And match response == schemas['404']

# =======================================================================
# 6. 🔵 FIELD VALIDATION
# =======================================================================

@contract @fields @get
Scenario: GET mis-datos - Campos obligatorios presentes
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + auxiliarToken
    When method GET
    Then status 200
    # Campos obligatorios en success response
    And match response.success == '#present'
    And match response.data == '#present'
    And match response.data.Id_Auxiliar == '#present'
    And match response.data.Nombres == '#present'
    And match response.data.Apellidos == '#present'
    And match response.data.Genero == '#present'
    And match response.data.Identificador_Nacional == '#present'
    And match response.data.Nombre_Usuario == '#present'
    And match response.data.Correo_Electronico == '#present'
    And match response.data.Celular == '#present'
    # Campo opcional - puede estar ausente
    And match response.data.Google_Drive_Foto_ID == '#ignore'

# =======================================================================
# 7. 🔵 DATA TYPES VALIDATION
# =======================================================================

@contract @data-types @get
Scenario: GET mis-datos - Tipos de datos correctos
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + auxiliarToken
    When method GET
    Then status 200
    And match response.success == '#boolean'
    And match response.data.Id_Auxiliar == '#number'
    And match response.data.Nombres == '#string'
    And match response.data.Apellidos == '#string'
    And match response.data.Genero == '#regex [MF]'
    And match response.data.Identificador_Nacional == '#string'
    And match response.data.Nombre_Usuario == '#string'
    And match response.data.Correo_Electronico == '#regex .+@.+'
    And match response.data.Celular == '#regex [0-9]{9}'

# =======================================================================
# 8. 🔵 BOUNDARY TESTING
# =======================================================================
@contract @boundary @get
Scenario: GET mis-datos - Sin token de autorización
    Given path "/api/mis-datos"
    When method GET
    Then status 401
    And match response.success == false
    And match response.message == '#string'

@contract @boundary @get
Scenario: GET mis-datos - Verificar que no acepta parámetros adicionales
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + auxiliarToken
    And param extraParam = 'valor'
    When method GET
    Then status 200