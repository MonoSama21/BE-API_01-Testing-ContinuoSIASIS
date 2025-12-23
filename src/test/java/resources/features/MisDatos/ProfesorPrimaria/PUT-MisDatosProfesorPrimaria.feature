@putMisDatosProfesorPrimaria @dailyTests
Feature: Actualizar datos del rol Profesor Primaria - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"
    * def result = call read('classpath:resources/features/Login/POST-LoginRolProfesorPrimaria.feature@tokenProfesorPrimaria')
    * def profesorPrimariaToken = result.token 

    @profprimaria
Scenario: Validar que el servicio de actualizar Mis Datos por el rol Profesor Primaria responde correctamente
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + profesorPrimariaToken
    And request 
    """
    {
        "Celular": "989729444",
        "Correo_Electronico": "maria.sanchez@educacion.com"
    }
    """
    When method PUT
    Then status 200