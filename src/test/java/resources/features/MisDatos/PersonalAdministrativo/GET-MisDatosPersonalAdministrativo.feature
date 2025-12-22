@misDatos
Feature: Retorna los datos personal del rol Personal Administrativo - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"
    * def result = call read('classpath:resources/features/Login/POST-LoginRolPersonalAdministrativo.feature@tokenPersonalAdministrativo')
    * def personalAdministrativoToken = result.token 

    @adminp
Scenario: Validar que el servicio GET Mis Datos Personal Administrativo responde correctamente
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + personalAdministrativoToken
    When method GET
    Then status 200