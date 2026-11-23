"""
Tests for passwords, accounts, roles, lockout and the security-event log.

Run from the project root:
    python -m unittest test_auth -v
"""
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from auth import passwords
from auth.service import (
    MAX_FAILED_ATTEMPTS,
    PERMISSIONS,
    ROLES,
    AuthError,
    AuthService,
    Session,
)
from auth.user_store import UserStore

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
GOOD = "correct horse battery"
CHEAP = 4  # scrypt cost for tests: the real cost is 2^17 and would make them slow


class PasswordHashTests(unittest.TestCase):
    def test_default_cost_is_the_owasp_minimum_and_verifies(self):
        stored = passwords.hash_password(GOOD)
        self.assertTrue(stored.startswith("scrypt$17$8$1$"))
        self.assertTrue(passwords.verify_password(GOOD, stored))

    def test_right_password_passes_and_wrong_ones_fail(self):
        stored = passwords.hash_password(GOOD, CHEAP)
        self.assertTrue(passwords.verify_password(GOOD, stored))
        for wrong in ["", "wrong", GOOD + " ", GOOD.upper(), GOOD[:-1]]:
            with self.subTest(wrong=wrong):
                self.assertFalse(passwords.verify_password(wrong, stored))

    def test_the_password_is_not_in_the_stored_text(self):
        self.assertNotIn(GOOD, passwords.hash_password(GOOD, CHEAP))

    def test_every_hash_has_its_own_salt(self):
        self.assertNotEqual(passwords.hash_password(GOOD, CHEAP),
                            passwords.hash_password(GOOD, CHEAP))

    def test_unicode_passwords_work(self):
        stored = passwords.hash_password("p\u00e4ssw\u00f6rd-\u4e2d\u6587-ok", CHEAP)
        self.assertTrue(passwords.verify_password("p\u00e4ssw\u00f6rd-\u4e2d\u6587-ok", stored))

    def test_a_changed_hash_no_longer_matches(self):
        stored = passwords.hash_password(GOOD, CHEAP)
        flipped = stored[:-3] + ("AAA" if not stored.endswith("AAA") else "BBB")
        self.assertFalse(passwords.verify_password(GOOD, flipped))

    def test_damaged_or_hostile_stored_values_give_false_not_errors(self):
        good = passwords.hash_password(GOOD, CHEAP)
        cases = [None, "", "garbage", "bcrypt$4$8$1$AAAA$AAAA", "scrypt$4$8$1$only-four",
                 "scrypt$x$8$1$AAAA$AAAA", "scrypt$30$8$1$AAAA$AAAA", "scrypt$4$8$1$!!$!!",
                 good.replace("scrypt$4", "scrypt$3"), 12345]
        for stored in cases:
            with self.subTest(stored=stored):
                self.assertFalse(passwords.verify_password(GOOD, stored))

    def test_a_password_that_is_not_text_gives_false(self):
        self.assertFalse(passwords.verify_password(None, passwords.hash_password(GOOD, CHEAP)))


class PasswordPolicyTests(unittest.TestCase):
    def assert_refused(self, password, username=""):
        with self.assertRaises(passwords.PasswordPolicyError):
            passwords.check_policy(password, username)

    def test_length_boundaries(self):
        self.assert_refused("a1b2c3d4e")          # 9 characters
        passwords.check_policy("a1b2c3d4e5")       # 10 characters
        passwords.check_policy("ab12" * 32)        # 128 characters
        self.assert_refused("ab12" * 32 + "x")     # 129 characters

    def test_repetitive_common_and_username_passwords_are_refused(self):
        self.assert_refused("aaaaaaaaaaaa")
        self.assert_refused("PassWord123")
        self.assert_refused("charles.chima", "Charles.Chima")

    def test_something_that_is_not_text_is_refused(self):
        self.assert_refused(None)
        self.assert_refused(1234567890)

    def test_a_long_plain_sentence_is_accepted(self):
        passwords.check_policy(GOOD, "charles")


class AuthFixture(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.folder.name, "auth.db")
        self.now = NOW
        self.store = UserStore(lambda: sqlite3.connect(self.path))
        self.store.init()
        self.auth = AuthService(self.store, clock=lambda: self.now, log_n=CHEAP)

    def tearDown(self):
        self.folder.cleanup()

    def make_admin(self, name="boss"):
        self.auth.create_first_admin(name, GOOD)
        return self.auth.login(name, GOOD)

    def make_user(self, admin, name, role):
        self.auth.create_user(admin, name, GOOD, role)
        return self.auth.login(name, GOOD)

    def assert_auth_error(self, code, call, *args):
        with self.assertRaises(AuthError) as caught:
            call(*args)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def events(self):
        return [(e["event"], e["username"]) for e in reversed(self.store.recent_events(100))]


class SetupAndUsernameTests(AuthFixture):
    def test_a_fresh_database_needs_setup_and_the_first_account_is_an_admin(self):
        self.assertTrue(self.auth.needs_setup())
        session = self.make_admin()
        self.assertFalse(self.auth.needs_setup())
        self.assertEqual((session.username, session.role), ("boss", "ADMIN"))

    def test_setup_can_only_be_done_once(self):
        self.make_admin()
        self.assert_auth_error("SETUP_DONE", self.auth.create_first_admin, "second", GOOD)

    def test_setup_refuses_a_weak_password(self):
        self.assert_auth_error("WEAK_PASSWORD", self.auth.create_first_admin, "boss", "short")
        self.assertTrue(self.auth.needs_setup())

    def test_usernames_must_be_3_to_32_safe_characters(self):
        for bad in ["", "ab", "a" * 33, "has space", "semi;colon", "quote'name", "<script>", None, 42]:
            with self.subTest(username=bad):
                self.assert_auth_error("INVALID_USERNAME", self.auth.create_first_admin, bad, GOOD)
        self.auth.create_first_admin("a.b-c_9", GOOD)

    def test_nothing_in_the_database_is_the_plain_password(self):
        self.make_admin()
        with sqlite3.connect(self.path) as conn:
            text = repr(conn.execute("SELECT * FROM users").fetchall())
        self.assertNotIn(GOOD, text)
        self.assertIn("scrypt$", text)


class LoginTests(AuthFixture):
    def test_correct_credentials_sign_in_and_are_remembered(self):
        self.make_admin()
        session = self.auth.login("boss", GOOD)
        self.assertIsInstance(session, Session)
        self.assertEqual(self.store.get("boss")["last_login"], NOW.isoformat())

    def test_usernames_are_not_case_sensitive(self):
        self.make_admin("Boss")
        self.assertEqual(self.auth.login("  bOSS ", GOOD).username, "Boss")

    def test_wrong_password_unknown_user_and_disabled_user_look_the_same(self):
        admin = self.make_admin()
        self.make_user(admin, "worker", "OPERATOR")
        self.auth.set_active(admin, "worker", False)
        messages = set()
        for name, password in [("boss", "wrong"), ("nobody", GOOD), ("worker", GOOD)]:
            error = self.assert_auth_error("INVALID_CREDENTIALS", self.auth.login, name, password)
            messages.add(error.message)
        self.assertEqual(len(messages), 1)

    def test_odd_input_is_just_a_failed_login(self):
        self.make_admin()
        for name, password in [(None, GOOD), ("boss", None), ("", ""), ("boss' OR '1'='1", "x")]:
            with self.subTest(name=name):
                self.assert_auth_error("INVALID_CREDENTIALS", self.auth.login, name, password)

    def test_sign_out_is_recorded(self):
        session = self.make_admin()
        self.auth.logout(session)
        self.assertIn(("LOGOUT", "boss"), self.events())


class LockoutTests(AuthFixture):
    def fail(self, times):
        for _ in range(times):
            self.assert_auth_error("INVALID_CREDENTIALS", self.auth.login, "boss", "wrong")

    def test_five_wrong_passwords_lock_the_account(self):
        self.make_admin()
        self.fail(MAX_FAILED_ATTEMPTS)
        self.assert_auth_error("ACCOUNT_LOCKED", self.auth.login, "boss", GOOD)
        self.assertIn(("LOGIN_LOCKED_OUT", "boss"), self.events())
        self.assertIn(("LOGIN_BLOCKED", "boss"), self.events())

    def test_four_wrong_passwords_do_not_lock_it(self):
        self.make_admin()
        self.fail(MAX_FAILED_ATTEMPTS - 1)
        self.assertEqual(self.auth.login("boss", GOOD).username, "boss")

    def test_a_success_resets_the_counter(self):
        self.make_admin()
        self.fail(4)
        self.auth.login("boss", GOOD)
        self.fail(4)
        self.assertEqual(self.auth.login("boss", GOOD).username, "boss")

    def test_the_lock_ends_after_five_minutes(self):
        self.make_admin()
        self.fail(MAX_FAILED_ATTEMPTS)
        self.now = NOW + timedelta(minutes=4, seconds=59)
        self.assert_auth_error("ACCOUNT_LOCKED", self.auth.login, "boss", GOOD)
        self.now = NOW + timedelta(minutes=5, seconds=1)
        self.assertEqual(self.auth.login("boss", GOOD).username, "boss")


class PermissionTests(AuthFixture):
    def test_each_role_gets_exactly_its_permissions(self):
        admin = self.make_admin()
        sessions = {"ADMIN": admin,
                    "OPERATOR": self.make_user(admin, "operator1", "OPERATOR"),
                    "VIEWER": self.make_user(admin, "viewer1", "VIEWER")}
        for role, session in sessions.items():
            for permission, roles in PERMISSIONS.items():
                with self.subTest(role=role, permission=permission):
                    self.assertEqual(self.auth.allowed(session, permission), role in roles)

    def test_nobody_signed_in_is_allowed_nothing(self):
        self.assertFalse(self.auth.allowed(None, "view_results"))
        self.assert_auth_error("PERMISSION_DENIED", self.auth.require, None, "scan")

    def test_an_unknown_permission_is_never_allowed(self):
        self.assertFalse(self.auth.allowed(self.make_admin(), "launch_missiles"))

    def test_a_denied_action_is_recorded(self):
        viewer = self.make_user(self.make_admin(), "viewer1", "VIEWER")
        self.assert_auth_error("PERMISSION_DENIED", self.auth.require, viewer, "scan")
        self.assertIn(("PERMISSION_DENIED", "viewer1"), self.events())

    def test_disabling_an_account_takes_effect_during_its_session(self):
        admin = self.make_admin()
        operator = self.make_user(admin, "operator1", "OPERATOR")
        self.assertTrue(self.auth.allowed(operator, "scan"))
        self.auth.set_active(admin, "operator1", False)
        self.assertFalse(self.auth.allowed(operator, "scan"))

    def test_changing_a_role_takes_effect_during_its_session(self):
        admin = self.make_admin()
        operator = self.make_user(admin, "operator1", "OPERATOR")
        self.auth.change_role(admin, "operator1", "VIEWER")
        self.assertFalse(self.auth.allowed(operator, "scan"))


class ManageAccountsTests(AuthFixture):
    def setUp(self):
        super().setUp()
        self.admin = self.make_admin()
        self.operator = self.make_user(self.admin, "operator1", "OPERATOR")

    def test_only_administrators_manage_accounts(self):
        calls = [(self.auth.create_user, ("x-user", GOOD, "VIEWER")),
                 (self.auth.change_role, ("boss", "VIEWER")),
                 (self.auth.set_active, ("boss", False)),
                 (self.auth.reset_password, ("boss", GOOD + "2")),
                 (self.auth.list_users, ()), (self.auth.recent_events, ())]
        for call, args in calls:
            with self.subTest(call=call.__name__):
                self.assert_auth_error("PERMISSION_DENIED", call, self.operator, *args)

    def test_create_user_checks_everything(self):
        self.assert_auth_error("USER_EXISTS", self.auth.create_user, self.admin, "OPERATOR1", GOOD, "VIEWER")
        self.assert_auth_error("INVALID_ROLE", self.auth.create_user, self.admin, "new-user", GOOD, "ROOT")
        self.assert_auth_error("WEAK_PASSWORD", self.auth.create_user, self.admin, "new-user", "short", "VIEWER")
        self.assert_auth_error("INVALID_USERNAME", self.auth.create_user, self.admin, "no", GOOD, "VIEWER")
        self.assertEqual([u["username"] for u in self.auth.list_users(self.admin)], ["boss", "operator1"])

    def test_the_last_administrator_cannot_be_disabled_or_demoted(self):
        self.assert_auth_error("LAST_ADMIN", self.auth.set_active, self.admin, "boss", False)
        self.assert_auth_error("LAST_ADMIN", self.auth.change_role, self.admin, "boss", "OPERATOR")
        self.assertTrue(self.auth.allowed(self.admin, "manage_users"))

    def test_with_two_administrators_one_can_be_demoted(self):
        self.auth.change_role(self.admin, "operator1", "ADMIN")
        self.auth.change_role(self.admin, "boss", "OPERATOR")
        self.assertEqual(self.store.get("boss")["role"], "OPERATOR")

    def test_a_disabled_account_cannot_sign_in_until_it_is_enabled(self):
        self.auth.set_active(self.admin, "operator1", False)
        self.assert_auth_error("INVALID_CREDENTIALS", self.auth.login, "operator1", GOOD)
        self.auth.set_active(self.admin, "operator1", True)
        self.assertEqual(self.auth.login("operator1", GOOD).role, "OPERATOR")

    def test_unknown_users_and_roles_are_reported(self):
        self.assert_auth_error("USER_NOT_FOUND", self.auth.set_active, self.admin, "ghost", False)
        self.assert_auth_error("INVALID_ROLE", self.auth.change_role, self.admin, "operator1", "ROOT")

    def test_an_administrator_reset_changes_the_password_and_clears_a_lock(self):
        for _ in range(MAX_FAILED_ATTEMPTS):
            self.assert_auth_error("INVALID_CREDENTIALS", self.auth.login, "operator1", "wrong")
        self.auth.reset_password(self.admin, "operator1", "a brand new passphrase")
        self.assert_auth_error("INVALID_CREDENTIALS", self.auth.login, "operator1", GOOD)
        self.assertEqual(self.auth.login("operator1", "a brand new passphrase").username, "operator1")

    def test_a_reset_must_meet_the_password_policy(self):
        self.assert_auth_error("WEAK_PASSWORD", self.auth.reset_password, self.admin, "operator1", "operator1")


class ChangeOwnPasswordTests(AuthFixture):
    def test_needs_the_current_password_and_a_good_new_one(self):
        session = self.make_admin()
        self.assert_auth_error("WRONG_PASSWORD", self.auth.change_own_password, session, "nope", "another long phrase")
        self.assert_auth_error("WEAK_PASSWORD", self.auth.change_own_password, session, GOOD, "short")
        self.auth.change_own_password(session, GOOD, "another long phrase")
        self.assert_auth_error("INVALID_CREDENTIALS", self.auth.login, "boss", GOOD)
        self.assertEqual(self.auth.login("boss", "another long phrase").username, "boss")
        self.assertIn(("PASSWORD_CHANGED", "boss"), self.events())


class SecurityEventLogTests(AuthFixture):
    def test_the_log_tells_the_story_and_never_holds_a_password(self):
        admin = self.make_admin()
        self.make_user(admin, "operator1", "OPERATOR")
        self.assert_auth_error("INVALID_CREDENTIALS", self.auth.login, "operator1", "secret-guess-one")
        self.auth.change_own_password(admin, GOOD, "a different long phrase")
        names = [event for event, _ in self.events()]
        for expected in ["FIRST_ADMIN_CREATED", "LOGIN_OK", "USER_CREATED", "LOGIN_FAILED", "PASSWORD_CHANGED"]:
            self.assertIn(expected, names)
        text = repr(self.store.recent_events(100))
        for secret in [GOOD, "secret-guess-one", "a different long phrase"]:
            self.assertNotIn(secret, text)

    def test_recent_events_come_newest_first_and_respect_the_limit(self):
        admin = self.make_admin()
        for _ in range(5):
            self.auth.login("boss", GOOD)
        newest = self.auth.recent_events(admin, 3)
        self.assertEqual(len(newest), 3)
        self.assertEqual(newest[0]["event"], "LOGIN_OK")

    def test_a_very_long_username_is_shortened_in_the_log(self):
        self.make_admin()
        self.assert_auth_error("INVALID_CREDENTIALS", self.auth.login, "x" * 5000, GOOD)
        self.assertEqual(len(self.store.recent_events(1)[0]["username"]), 64)


class StoreTests(AuthFixture):
    def test_accounts_survive_a_restart(self):
        self.make_admin()
        again = AuthService(UserStore(lambda: sqlite3.connect(self.path)), log_n=CHEAP)
        self.assertFalse(again.needs_setup())
        self.assertEqual(again.login("boss", GOOD).role, "ADMIN")

    def test_the_database_itself_refuses_bad_roles_and_duplicate_names(self):
        self.make_admin()
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.add("boss", "hash", "ADMIN", NOW.isoformat())
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.add("other", "hash", "SUPERUSER", NOW.isoformat())

    def test_the_role_list_matches_the_database_rule(self):
        for role in ROLES:
            self.store.add(f"user-{role.lower()}", "hash", role, NOW.isoformat())
        self.assertEqual(self.store.count_users(), 3)


if __name__ == "__main__":
    unittest.main()