Feature: Signing in and permissions
  As the owner of a small business
  I want only the people I have set up to use the scanner, each with the right level of access
  So that scanning power and scan results stay in the right hands

  Background:
    Given a new installation

  Scenario: The first run creates an administrator
    Then the system asks for an administrator account
    When I create the administrator "boss" with password "correct horse battery"
    Then "boss" can sign in with "correct horse battery"
    And the system no longer asks for an administrator account

  Scenario: There is no built-in account
    When I try to sign in as "admin" with password "admin"
    Then sign-in is refused with reason "INVALID_CREDENTIALS"

  Scenario Outline: Weak passwords are refused
    When I try to create the administrator "boss" with password "<password>"
    Then account creation is refused with reason "WEAK_PASSWORD"

    Examples:
      | password     |
      | short        |
      | aaaaaaaaaaaa |
      | PASSWORD123  |
      | 1234567890   |

  Scenario: A wrong password and an unknown user look identical
    Given an administrator "boss" with password "correct horse battery" is set up
    When I try to sign in as "boss" with password "wrong"
    Then the message shown is "Invalid username or password."
    When I try to sign in as "nobody" with password "wrong"
    Then the message shown is "Invalid username or password."

  Scenario: Five wrong passwords lock the account for five minutes
    Given an administrator "boss" with password "correct horse battery" is set up
    When I enter the wrong password 5 times for "boss"
    And I try to sign in as "boss" with password "correct horse battery"
    Then sign-in is refused with reason "ACCOUNT_LOCKED"
    When 6 minutes pass
    Then "boss" can sign in with "correct horse battery"

  Scenario: An operator can scan but a viewer cannot
    Given an administrator "boss" with password "correct horse battery" is set up
    And "boss" creates the user "operator1" as OPERATOR
    And "boss" creates the user "viewer1" as VIEWER
    Then "operator1" is allowed to "scan"
    And "viewer1" is not allowed to "scan"
    And "viewer1" is allowed to "view_results"
    And "viewer1" is not allowed to "manage_users"

  Scenario: Only an administrator can create accounts
    Given an administrator "boss" with password "correct horse battery" is set up
    And "boss" creates the user "operator1" as OPERATOR
    When "operator1" tries to create the user "friend1" as VIEWER
    Then the action is refused with reason "PERMISSION_DENIED"

  Scenario: The last administrator cannot be disabled
    Given an administrator "boss" with password "correct horse battery" is set up
    When "boss" tries to disable "boss"
    Then the action is refused with reason "LAST_ADMIN"

  Scenario: A disabled account cannot sign in
    Given an administrator "boss" with password "correct horse battery" is set up
    And "boss" creates the user "operator1" as OPERATOR
    When "boss" disables "operator1"
    And I try to sign in as "operator1" with password "a long shared passphrase"
    Then sign-in is refused with reason "INVALID_CREDENTIALS"

  Scenario: Disabling a signed-in account takes effect straight away
    Given an administrator "boss" with password "correct horse battery" is set up
    And "boss" creates the user "operator1" as OPERATOR
    And "operator1" is allowed to "scan"
    When "boss" disables "operator1"
    Then "operator1" is not allowed to "scan"

  Scenario: Passwords are stored as hashes and never as text
    Given an administrator "boss" with password "correct horse battery" is set up
    Then the stored password for "boss" is a hash that does not contain "correct horse battery"
