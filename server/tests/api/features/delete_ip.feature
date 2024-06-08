Feature: Delete IP from black or white list

  @serial
  Scenario: Delete IP from black list when ip exists
    Given black list with ip 127.1.0.0/24
    When delete ip 127.1.0.0/24 from black list
    Then response status is ok
    And black list hasn't ip 127.1.0.0/24

  @serial
  Scenario: Delete IP from black list when ip doesn't exist
    Given black list without ip 128.1.0.0/24
    When delete ip 128.1.0.0/24 from black list
    Then response status is ok
    And black list hasn't ip 128.1.0.0/24

  @serial
  Scenario: Delete IP from white list when ip exists
    Given white list with ip 129.1.0.0/24
    When delete ip 129.1.0.0/24 from white list
    Then response status is ok
    And white list hasn't ip 129.1.0.0/24

  @serial
  Scenario: Delete IP from white list when ip doesn't exist
    Given white list without ip 130.1.0.0/24
    When delete ip 130.1.0.0/24 from white list
    Then response status is ok
    And white list hasn't ip 130.1.0.0/24