@putMisDatosMiFotoPerfilDirectivo @dailyTests
Feature: Actualizar datos del rol Directivo - Pruebas de Contrato API

Background:
    * url urlBase
    * def result = call read('classpath:resources/features/Login/POST-LoginRolDirectivo.feature@tokenDirectivo')
    * def directivoToken = result.token

Scenario: Validar que el servicio de actualizar mi foto de perfil por el rol Directivo responde correctamente
    Given path "/api/mis-datos/mi-foto-perfil"
    And header Authorization = 'Bearer ' + directivoToken
    And multipart file foto = { read: 'classpath:resources/functional/data/img/foto-perfil.png', filename: 'foto-perfil.png', contentType: 'image/png' }
    When method PUT
    Then status 200