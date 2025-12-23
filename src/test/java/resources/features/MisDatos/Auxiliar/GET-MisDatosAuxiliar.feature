@misDatos @dailyTests
Feature: Retorna los datos personal del rol Auxiliar - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"
    * def result = call read('classpath:resources/features/Login/POST-LoginRolAuxiliar.feature@tokenAuxiliar')
    * def auxiliarToken = result.token 

Scenario: Validar que el servicio GET Mis Datos Auxiliar responde correctamente
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + auxiliarToken
    When method GET
    Then status 200