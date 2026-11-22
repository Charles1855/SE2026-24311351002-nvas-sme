from datetime import timedelta

from behave import given, step, then, when

from auth.service import AuthError

SHARED_PASSWORD = "a long shared passphrase"


def attempt(context, action, *args):
    """Run an action and remember whether it was refused."""
    context.auth_error = None
    try:
        return action(*args)
    except AuthError as error:
        context.auth_error = error
        return None


def sign_in(context, name, password):
    session = context.auth.login(name, password)
    context.sessions[name] = session
    return session


# ---------- Given ----------

@given("a new installation")
def given_new_installation(context):
    assert context.auth.needs_setup()


@given('an administrator "{name}" with password "{password}" is set up')
def given_admin(context, name, password):
    context.auth.create_first_admin(name, password)
    context.passwords[name] = password
    sign_in(context, name, password)


@given('"{admin}" creates the user "{name}" as {role}')
def given_user(context, admin, name, role):
    context.auth.create_user(context.sessions[admin], name, SHARED_PASSWORD, role)
    context.passwords[name] = SHARED_PASSWORD
    sign_in(context, name, SHARED_PASSWORD)


# ---------- When ----------

@when('I create the administrator "{name}" with password "{password}"')
def when_create_admin(context, name, password):
    context.auth.create_first_admin(name, password)


@when('I try to create the administrator "{name}" with password "{password}"')
def when_try_create_admin(context, name, password):
    attempt(context, context.auth.create_first_admin, name, password)


@when('I try to sign in as "{name}" with password "{password}"')
def when_try_sign_in(context, name, password):
    context.auth_session = attempt(context, context.auth.login, name, password)


@when('I enter the wrong password {count:d} times for "{name}"')
def when_wrong_passwords(context, count, name):
    for _ in range(count):
        attempt(context, context.auth.login, name, "definitely the wrong one")


@when("{minutes:d} minutes pass")
def when_time_passes(context, minutes):
    context.now = context.now + timedelta(minutes=minutes)


@when('"{actor}" tries to create the user "{name}" as {role}')
def when_try_create_user(context, actor, name, role):
    attempt(context, context.auth.create_user, context.sessions[actor], name, SHARED_PASSWORD, role)


@when('"{actor}" tries to disable "{name}"')
def when_try_disable(context, actor, name):
    attempt(context, context.auth.set_active, context.sessions[actor], name, False)


@when('"{actor}" disables "{name}"')
def when_disable(context, actor, name):
    context.auth.set_active(context.sessions[actor], name, False)


# ---------- Then ----------

@then("the system asks for an administrator account")
def then_asks(context):
    assert context.auth.needs_setup()


@then("the system no longer asks for an administrator account")
def then_no_longer_asks(context):
    assert not context.auth.needs_setup()


@then('"{name}" can sign in with "{password}"')
def then_can_sign_in(context, name, password):
    assert sign_in(context, name, password).username.lower() == name.lower()


@then('sign-in is refused with reason "{code}"')
def then_sign_in_refused(context, code):
    assert context.auth_error is not None, "sign-in was not refused"
    assert context.auth_error.code == code, f"expected {code}, got {context.auth_error.code}"


@then('account creation is refused with reason "{code}"')
def then_creation_refused(context, code):
    then_sign_in_refused(context, code)


@then('the action is refused with reason "{code}"')
def then_action_refused(context, code):
    then_sign_in_refused(context, code)


@then('the message shown is "{message}"')
def then_message(context, message):
    assert context.auth_error is not None and context.auth_error.message == message


@step('"{name}" is allowed to "{permission}"')
def then_allowed(context, name, permission):
    assert context.auth.allowed(context.sessions[name], permission)


@step('"{name}" is not allowed to "{permission}"')
def then_not_allowed(context, name, permission):
    assert not context.auth.allowed(context.sessions[name], permission)


@then('the stored password for "{name}" is a hash that does not contain "{password}"')
def then_stored_as_hash(context, name, password):
    stored = context.store.get(name)["password_hash"]
    assert stored.startswith("scrypt$") and password not in stored, stored