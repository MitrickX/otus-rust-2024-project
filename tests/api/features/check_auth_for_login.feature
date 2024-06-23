Feature: Check authorization allowance for current login

  @serial
  Scenario: Authorization attempts hit rate limit by login
    Given reset rate limter for login test-login-1234
    
    When trying authorization with login test-login-1234 max allowed times
    Then each response is Err(Unauthenticated)

    When trying authorization with login test-login-1234
    Then response is Err(PermissionDenied)

    When wait for 1 minute
    And trying authorization with login test-login-1234 max allowed times
    Then each response is Err(Unauthenticated)

    When trying authorization with login test-login-1234
    Then response is Err(PermissionDenied)

    # different login, hence allowed to authorize for now
    When trying authorization with login test-login-5678
    Then each response is Err(Unauthenticated)