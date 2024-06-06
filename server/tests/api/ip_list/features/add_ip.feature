Feature: Add IP in black or white list
  
  Scenario: Add IP in black list
    Given black list
    When add ip 127.0.0.0/24
    Then ok

  Scenario: Add IP in white list
    Given white list
    When add ip 127.0.0.0/24
    Then ok