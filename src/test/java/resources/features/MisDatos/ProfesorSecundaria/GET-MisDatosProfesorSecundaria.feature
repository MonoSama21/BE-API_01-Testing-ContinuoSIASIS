@misDatos @dailyTests
Feature: Retorna los datos personal del rol Profesor Secundaria - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"
    * def result = call read('classpath:resources/features/Login/POST-LoginRolProfesorSecundaria.feature@tokenProfesorSecundaria')
    * def profesorSecundariaToken = result.token 

    @profsecundaria
Scenario: Validar que el servicio GET Mis Datos Profesor Secundaria responde correctamente
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + profesorSecundariaToken
    When method GET
    Then status 200