@misDatos
Feature: Retorna los datos personal del rol Profesor Primaria - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"
    * def result = call read('classpath:resources/features/Login/POST-LoginRolProfesorPrimaria.feature@tokenProfesorPrimaria')
    * def profesorPrimariaToken = result.token 

    @profprimaria
Scenario: Validar que el servicio GET Mis Datos Profesor Primaria responde correctamente
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + profesorPrimariaToken
    When method GET
    Then status 200