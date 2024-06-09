Feature: Check authorization allowance for current login

  @serial
  Scenario: Authorization attempts hit rate limit by login
    Given reset rate limter for login test-login-1234
    
    When checking authorization with login test-login-1234 max allowed times
    Then each response is Ok(true)

    When checking authorization with login test-login-1234
    Then response is Ok(false)

    When wait for 1 minute
    And checking authorization with login test-login-1234 max allowed times
    Then each response is Ok(true)

    When checking authorization with login test-login-1234
    Then response is Ok(false)

    # different login, hence allowed to authorize for now
    When checking authorization with login test-login-5678
    Then each response is Ok(true)