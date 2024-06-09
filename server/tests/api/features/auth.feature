Feature: Check authorization allowance

  @serial
  Scenario: Authorization is not allowed cause ip in black list
    Given empty black list

    When add ip 127.0.0.1 to black list
    And checking authorization with ip 127.0.0.1

    Then response is Ok(false)

  @serial
  Scenario: Authorization is not allowed cause subnet ip in black list
    Given empty black list

    When add ip 128.0.0.0/24 to black list
    And checking authorization with ip 128.0.0.1

    Then response is Ok(false)

  @serial
  Scenario: Authorization is allowed cause ip in white list and not in black list
    Given empty black list
    And empty white list

    When add ip 129.0.0.1 to white list
    And checking authorization with ip 129.0.0.1

    Then response is Ok(true)

  @serial
  Scenario: Authorization is allowed cause subnet ip in white list and not in black list
    Given empty black list
    And empty white list

    When add ip 130.0.0.0/24 to white list
    And checking authorization with ip 130.0.0.1

    Then response is Ok(true)

  @serial
  Scenario: Authorization attempts hit rate limit by ip
    Given empty black list
    And empty white list
    And reset rate limter for ip 127.0.0.1

    When checking authorization with ip 127.0.0.1 max allowed times
    Then each response is Ok(true)

    When checking authorization with ip 127.0.0.1
    Then response is Ok(false)

    # different ip, so allowed to authorize anyway
    When checking authorization with ip 128.0.0.1
    Then each response is Ok(true)