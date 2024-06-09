Feature: Check authorization allowance

  @serial
  Scenario: Authorization is not allowed cause ip in black list
    Given empty black list

    When add ip 127.0.0.1 to black list
    And checking authorization with ip 127.0.0.1

    Then response status is ok
    And authorization is not allowed

  @serial
  Scenario: Authorization is not allowed cause subnet ip in black list
    Given empty black list

    When add ip 128.0.0.0/24 to black list
    And checking authorization with ip 128.0.0.1

    Then response status is ok
    And authorization is not allowed

  @serial
  Scenario: Authorization is allowed cause ip in white list and not in black list
    Given empty black list
    And empty white list

    When add ip 129.0.0.1 to white list
    And checking authorization with ip 129.0.0.1

    Then response status is ok
    And authorization is allowed

  @serial
  Scenario: Authorization is allowed cause subnet ip in white list and not in black list
    Given empty black list
    And empty white list

    When add ip 130.0.0.0/24 to white list
    And checking authorization with ip 130.0.0.1

    Then response status is ok
    And authorization is allowed

  @serial
  Scenario: Authorization is allowed cause subnet ip in white list and not in black list
    Given empty black list
    And empty white list
    And reset rate limter for ip 127.0.0.1

    When checking authorization with ip 127.0.0.1 max allowed times
    And checking authorization with ip 127.0.0.1

    Then response status is ok
    And authorization is not allowed

    # different ip, so allowed to authorize
    When checking authorization with ip 128.0.0.1

    Then response status is ok
    And authorization is allowed