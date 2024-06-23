Feature: Add role

  @serial
  Scenario: Add role without permissions
    When add role without permissions
    Then response is Ok(token)
    And token permissions are empty

  @serial
  Scenario: Add role with permissions view_ip_list, manage_role
    When add role with permissions view_ip_list, manage_role
    Then response is Ok(token)
    And token permissions are view_ip_list, manage_role