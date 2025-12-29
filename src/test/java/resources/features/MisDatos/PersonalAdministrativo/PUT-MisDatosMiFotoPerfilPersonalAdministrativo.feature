@putMisDatosMiFotoPerfilPersonalAdministrativo @dailyTests
Feature: Actualizar datos del rol Personal Administrativo - Pruebas de Contrato API

Background:
    * url urlBase
    * def result = call read('classpath:resources/features/Login/POST-LoginRolPersonalAdministrativo.feature@tokenPersonalAdministrativo')
    * def personalAdministrativoToken = result.token

    @fototro
Scenario: Validar que el servicio de actualizar mi foto de perfil por el rol Personal Administrativo responde correctamente
    Given path "/api/mis-datos/mi-foto-perfil"
    And header Authorization = 'Bearer ' + personalAdministrativoToken
    And multipart file foto = { read: 'classpath:resources/functional/data/img/foto-perfil.png', filename: 'foto-perfil.png', contentType: 'image/png' }
    When method PUT
    Then status 200