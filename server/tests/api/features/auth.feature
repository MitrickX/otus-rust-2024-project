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
    When checking authorization with ip 128.0.0.1
    Then response status is ok
    And authorization is not allowed

  @serial
  Scenario: Authorization is allowed cause ip in white list and not in black list
    Given empty black list
    And empty white list
    When add ip 129.0.0.1 to white list
    When checking authorization with ip 129.0.0.1
    Then response status is ok
    And authorization is allowed

  # Scenario: Authorization is allowed cause subnet ip in white list and not in black list
  #   Given empty black list
  #   And empty white list
  #   When add ip 137.0.0.1 to white list
  #   When checking authorization with ip 137.0.0.1
  #   Then response status is ok
  #   And authorization is allowed