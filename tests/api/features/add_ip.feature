Feature: Add IP in black or white list
  
  @serial
  Scenario: Add IP in black list when ip exists
    Given black list with ip 127.0.0.0/24
    When add ip 127.0.0.0/24 to black list
    Then response is Ok()
    And black list has ip 127.0.0.0/24

  @serial
  Scenario: Add IP in black list when ip doesn't exist
    Given black list without ip 128.0.0.0/24
    When add ip 128.0.0.0/24 to black list
    Then response is Ok()
    And black list has ip 128.0.0.0/24

  @serial
  Scenario: Add IP in white list when ip exists
    Given white list with ip 129.0.0.0/24
    When add ip 129.0.0.0/24 to white list
    Then response is Ok()
    And white list has ip 129.0.0.0/24

  @serial
  Scenario: Add IP in white list when ip doesn't exist
    Given white list without ip 130.0.0.0/24
    When add ip 130.0.0.0/24 to white list
    Then response is Ok()
    And white list has ip 130.0.0.0/24