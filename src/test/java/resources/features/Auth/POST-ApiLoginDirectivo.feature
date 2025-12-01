Feature: Login de usuario directivo

Background: Pre-Condiciones
    * url urlBase
    * header Content-Type = "application/json"

Scenario: Validar que el directivo puede hacer un login exitoso
    Given path "api/login/directivo"
    And request 
    """
    {
        "Nombre_Usuario": "director.asuncion8",
        "Contraseña": "15430124"
    }
    """
    When method POST
    Then status 200