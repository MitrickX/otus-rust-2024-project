Feature: Check authorization allowance for current password

  @serial
  Scenario: Authorization attempts hit rate limit by password
    Given reset rate limter for password test-password-1234
    
    When checking authorization with password test-password-1234 max allowed times
    Then each response is Ok(true)

    When checking authorization with password test-password-1234
    Then response is Ok(false)

    When wait for 1 minute
    And checking authorization with password test-password-1234 max allowed times
    Then each response is Ok(true)

    When checking authorization with password test-password-1234
    Then response is Ok(false)

    # different password, hence allowed to authorize for now
    When checking authorization with password test-password-5678
    Then each response is Ok(true)