@putMisDatosPersonalAdministrativo @dailyTests
Feature: Actualizar datos del rol Personal Administrativo - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"
    * def result = call read('classpath:resources/features/Login/POST-LoginRolPersonalAdministrativo.feature@tokenPersonalAdministrativo')
    * def personalAdministrativoToken = result.token 

    @administrativo
Scenario: Validar que el servicio de actualizar Mis Datos por el rol Personal Administrativo responde correctamente
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + personalAdministrativoToken
    And request 
    """
    {
        "Celular": "989728164"
    }
    """
    When method PUT
    Then status 200