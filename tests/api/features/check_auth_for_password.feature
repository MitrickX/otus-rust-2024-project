Feature: Check authorization allowance for current password

  @serial
  Scenario: Authorization attempts hit rate limit by password
    Given reset rate limter for password test-password-1234
    
    When trying authorization with password test-password-1234 max allowed times
    Then each response is Err(Unauthenticated)

    When trying authorization with password test-password-1234
    Then response is Err(PermissionDenied)

    When wait for 1 minute
    And trying authorization with password test-password-1234 max allowed times
    Then each response is Err(Unauthenticated)

    When trying authorization with password test-password-1234
    Then response is Err(PermissionDenied)

    # different password, hence allowed to authorize for now
    When trying authorization with password test-password-5678
    Then each response is Err(Unauthenticated)