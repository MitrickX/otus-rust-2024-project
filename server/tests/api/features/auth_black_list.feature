Feature: Check authorization allowance

  Scenario: IP conform black list hence authorization is not allowed
    Given black list with ip 127.0.0.1
    When checking authorization with ip 127.0.0.1
    Then response status is ok
    And authorization is not allowed

  Scenario: IP conform black list by subnet hence authorization is not allowed
    Given black list without ip 127.0.0.1
    And black list with ip 127.0.0.1/24
    When checking authorization with ip 127.0.0.1
    Then response status is ok
    And authorization is not allowed