@putMisDatosTutorSecundaria @dailyTests
Feature: Actualizar datos del rol Tutor Secundaria - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"
    * def result = call read('classpath:resources/features/Login/POST-LoginRolTutorSecundaria.feature@tokenTutorSecundaria')
    * def tutorSecundariaToken = result.token 

    @tutorsecundaria
Scenario: Validar que el servicio de actualizar Mis Datos por el rol Tutor Secundaria responde correctamente
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + tutorSecundariaToken
    And request 
    """
    {
        "Celular": "989728139"
    }
    """
    When method PUT
    Then status 200