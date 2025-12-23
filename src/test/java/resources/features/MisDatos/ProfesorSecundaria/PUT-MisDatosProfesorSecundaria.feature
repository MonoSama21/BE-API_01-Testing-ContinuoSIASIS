@putMisDatosProfesorSecundaria @dailyTests
Feature: Actualizar datos del rol Profesor Secundaria - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"
    * def result = call read('classpath:resources/features/Login/POST-LoginRolProfesorSecundaria.feature@tokenProfesorSecundaria')
    * def profesorSecundariaToken = result.token 

    @profsecundaria
Scenario: Validar que el servicio de actualizar Mis Datos por el rol Profesor Secundaria responde correctamente
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + profesorSecundariaToken
    And request 
    """
        {
            "Celular": "989711734",
            "Correo_Electronico": "sofia.vargas@educacion.com"
        }
    """
    When method PUT
    Then status 200