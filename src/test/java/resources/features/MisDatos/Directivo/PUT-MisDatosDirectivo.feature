@putMisDatosDirectivo @dailyTests
Feature: Actualizar datos del rol Directivo - Pruebas de Contrato API

Background:
    * url urlBase
    * header Content-Type = "application/json"
    * def result = call read('classpath:resources/features/Login/POST-LoginRolDirectivo.feature@tokenDirectivo')
    * def directivoToken = result.token 

    @actu
Scenario: Validar que el servicio de actualizar Mis Datos por el rol Directivo responde correctamente
    Given path "/api/mis-datos"
    And header Authorization = 'Bearer ' + directivoToken
    And request 
    """
    {
        "Identificador_Nacional":"15430124",
        "Genero": "F",
        "Nombres": "Elena Serafina",
        "Apellidos": "Cullanco Espilco",
        "Celular": "989729659"
    }
    """
    When method PUT
    Then status 200