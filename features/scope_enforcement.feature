Feature: Scope enforcement
  As a part-time IT officer at a small business
  I want the scanner to refuse anything outside my signed authorisation
  So that I never scan a network I am not allowed to scan

  Background:
    Given a signed scope for "192.168.56.0/24" valid from "2026-01-01T00:00:00+00:00" to "2027-12-31T23:59:59+00:00"
    And the clock shows "2026-11-20T12:00:00+00:00"

  Scenario: A device inside the scope is scanned
    When I ask to scan "192.168.56.102"
    Then the target is accepted
    And one scan engine was started

  Scenario: A range inside the scope is accepted by the guard
    When I ask the guard about "192.168.56.0/25"
    Then the target is accepted

  Scenario Outline: Targets outside the scope or in the wrong format are refused before anything is sent
    When I ask to scan "<target>"
    Then the scan is refused with reason "<reason>"
    And no scan engine was started
    And the refusal is recorded in the audit log

    Examples: Outside the authorised network
      | target          | reason       |
      | 192.168.57.1    | OUT_OF_SCOPE |
      | 192.168.55.255  | OUT_OF_SCOPE |
      | 192.168.56.0/23 | OUT_OF_SCOPE |
      | 10.0.0.5        | OUT_OF_SCOPE |
      | 172.16.0.1      | OUT_OF_SCOPE |
      | 192.0.2.10      | OUT_OF_SCOPE |
      | 198.51.100.7    | OUT_OF_SCOPE |
      | 203.0.113.9     | OUT_OF_SCOPE |
      | 0.0.0.0/0       | OUT_OF_SCOPE |
      | 127.0.0.1       | OUT_OF_SCOPE |
      | 2001:db8::1     | OUT_OF_SCOPE |

    Examples: Wrong format
      | target                     | reason         |
      | 192.168.56.5/24            | INVALID_TARGET |
      | 192.168.56.256             | INVALID_TARGET |
      | 192.168.056.001            | INVALID_TARGET |
      | localhost                  | INVALID_TARGET |
      | example.com                | INVALID_TARGET |
      | 192.168.56.1-50            | INVALID_TARGET |
      | 192.168.56.1 --script vuln | INVALID_TARGET |
      | http://192.168.56.1        | INVALID_TARGET |
      | 192.168.56.1:80            | INVALID_TARGET |

  Scenario: A scope that has expired blocks every scan
    Given the clock shows "2028-02-01T00:00:00+00:00"
    When I ask to scan "192.168.56.102"
    Then the scan is refused with reason "SCOPE_EXPIRED"
    And no scan engine was started

  Scenario: A scope that is not valid yet blocks every scan
    Given the clock shows "2025-12-31T00:00:00+00:00"
    When I ask to scan "192.168.56.102"
    Then the scan is refused with reason "SCOPE_NOT_YET_VALID"
    And no scan engine was started

  Scenario: A scope file edited after signing is rejected
    Given the scope file was edited after signing to authorise "10.0.0.0/24"
    When I load the scope
    Then loading the scope fails with reason "SIGNATURE_INVALID"

  Scenario: A scope signed by a key the scanner does not trust is rejected
    Given the scope was signed by a key the scanner does not trust
    When I load the scope
    Then loading the scope fails with reason "SIGNATURE_INVALID"

  Scenario: A scope that authorises far too much is rejected
    Given a signed scope for "0.0.0.0/0" valid from "2026-01-01T00:00:00+00:00" to "2027-12-31T23:59:59+00:00"
    When I load the scope
    Then loading the scope fails with reason "SCOPE_TOO_BROAD"

  Scenario: A missing scope file means nothing can be scanned
    Given there is no scope file
    When I load the scope
    Then loading the scope fails with reason "SCOPE_MISSING"
