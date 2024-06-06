Feature: Add IP in black or white list
  
  Scenario: Add IP in black list
    Given API Client
    When add ip 127.0.0.0/24 to black list
    Then response is ok

  Scenario: Add IP in white list
    Given API Client
    When add ip 127.0.0.0/24 to white list
    Then response is ok