@putMisDatosAuxiliar @dailyTests
Feature: Actualizar datos del rol Auxiliar - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"
    * def result = call read('classpath:resources/features/Login/POST-LoginRolAuxiliar.feature@tokenAuxiliar')
    * def auxiliarToken = result.token 

    @auxiliar
Scenario: Validar que el servicio de actualizar Mis Datos por el rol Auxiliar responde correctamente
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + auxiliarToken
    And request 
    """
    {
        "Celular": "989728734",
        "Correo_Electronico": "rosa.mendoza@educacion.com"
    }
    """
    When method PUT
    Then status 200