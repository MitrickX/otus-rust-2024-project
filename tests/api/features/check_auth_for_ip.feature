Feature: Check authorization allowance for current ip

  @serial
  Scenario: Authorization is not allowed cause ip in black list
    Given empty black list

    When add ip 127.0.0.1 to black list
    And trying authorization with ip 127.0.0.1

    Then response is Err(PermissionDenied)

  @serial
  Scenario: Authorization is not allowed cause subnet ip in black list
    Given empty black list

    When add ip 128.0.0.0/24 to black list
    And trying authorization with ip 128.0.0.1

    Then response is Err(PermissionDenied)

  @serial
  Scenario: Authorization is allowed cause ip in white list and not in black list
    Given empty black list
    And empty white list

    When add ip 129.0.0.1 to white list
    And trying authorization with ip 129.0.0.1

    Then response is Err(Unauthenticated)

  @serial
  Scenario: Authorization is allowed cause subnet ip in white list and not in black list
    Given empty black list
    And empty white list

    When add ip 130.0.0.0/24 to white list
    And trying authorization with ip 130.0.0.1

    Then response is Err(Unauthenticated)

  @serial
  Scenario: Authorization attempts hit rate limit by ip
    Given empty black list
    And empty white list
    And reset rate limter for ip 127.0.0.1

    When trying authorization with ip 127.0.0.1 max allowed times
    Then each response is Err(Unauthenticated)

    When trying authorization with ip 127.0.0.1
    Then response is Err(PermissionDenied)

    When wait for 1 minute
    And trying authorization with ip 127.0.0.1 max allowed times
    Then each response is Err(Unauthenticated)

    When trying authorization with ip 127.0.0.1
    Then response is Err(PermissionDenied)

    # different ip, hence allowed to authorize for now
    When trying authorization with ip 128.0.0.1
    Then each response is Err(Unauthenticated)