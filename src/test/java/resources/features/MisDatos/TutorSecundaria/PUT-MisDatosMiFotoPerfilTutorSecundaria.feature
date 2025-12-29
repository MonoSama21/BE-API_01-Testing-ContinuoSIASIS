@putMisDatosMiFotoPerfilTutorSecundaria @dailyTests
Feature: Actualizar datos del rol Tutor Secundaria - Pruebas de Contrato API

Background:
    * url urlBase
    * def result = call read('classpath:resources/features/Login/POST-LoginRolTutorSecundaria.feature@tokenTutorSecundaria')
    * def tutorSecundariaToken = result.token

    @fototuto
Scenario: Validar que el servicio de actualizar mi foto de perfil por el rol Tutor Secundaria responde correctamente
    Given path "/api/mis-datos/mi-foto-perfil"
    And header Authorization = 'Bearer ' + tutorSecundariaToken
    And multipart file foto = { read: 'classpath:resources/functional/data/img/foto-perfil.png', filename: 'foto-perfil.png', contentType: 'image/png' }
    When method PUT
    Then status 200