@misDatos @dailyTests
Feature: Retorna los datos personal del rol Tutor Secundaria - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"
    * def result = call read('classpath:resources/features/Login/POST-LoginRolTutorSecundaria.feature@tokenTutorSecundaria')
    * def tutorSecundariaToken = result.token 

    @tutorsecundaria
Scenario: Validar que el servicio GET Mis Datos Tutor Secundaria responde correctamente
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + tutorSecundariaToken
    When method GET
    Then status 200