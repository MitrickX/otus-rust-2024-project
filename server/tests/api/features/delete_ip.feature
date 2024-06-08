Feature: Delete IP from black or white list

  Scenario: Delete IP from black list when ip exists
    Given black list with ip 131.0.0.0/24
    When delete ip 131.0.0.0/24 from black list
    Then response status is ok
    And black list hasn't ip 131.0.0.0/24

  Scenario: Delete IP from black list when ip doesn't exist
    Given black list without ip 132.0.0.0/24
    When delete ip 132.0.0.0/24 from black list
    Then response status is ok
    And black list hasn't ip 132.0.0.0/24

  Scenario: Delete IP from white list when ip exists
    Given white list with ip 133.0.0.0/24
    When delete ip 133.0.0.0/24 from white list
    Then response status is ok
    And white list hasn't ip 133.0.0.0/24

  Scenario: Delete IP from white list when ip doesn't exist
    Given white list without ip 134.0.0.0/24
    When delete ip 134.0.0.0/24 from white list
    Then response status is ok
    And white list hasn't ip 134.0.0.0/24