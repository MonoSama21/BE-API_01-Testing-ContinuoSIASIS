@getMisDatos @dailyTests
Feature: Retorna los datos personal del rol Directivo - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"
    * def result = call read('classpath:resources/features/Login/POST-LoginRolDirectivo.feature@tokenDirectivo')
    * def directivoToken = result.token 

Scenario: Validar que el servicio GET Mis Datos Directivo responde correctamente
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + directivoToken
    When method GET
    Then status 200