import json
from datetime import datetime

from behave import given, then, when
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scanner.port_scanner import PortScanner
from scanner.scope_guard import ScopeError, ScopeGuard, sign_scope


def build_guard(context):
    """Write the scope file as the scenario describes it, then load it like the app does."""
    if not context.no_file:
        document = {"scope": context.scope,
                    "signature": sign_scope(context.scope, context.signer)}
        if context.tamper:
            context.tamper(document)
        with open(context.scope_path, "w", encoding="utf-8") as handle:
            json.dump(document, handle)
    context.guard = ScopeGuard.from_files(
        context.scope_path, context.public_path, clock=lambda: context.now)
    return context.guard


# ---------- Given ----------

@given('a signed scope for "{network}" valid from "{start}" to "{end}"')
def given_signed_scope(context, network, start, end):
    context.scope = {
        "organisation": "Demo SME Ltd",
        "authorised_by": "A. Owner, Owner",
        "networks": [network],
        "not_before": start,
        "not_after": end,
    }


@given('the clock shows "{moment}"')
def given_clock(context, moment):
    context.now = datetime.fromisoformat(moment)


@given('the scope file was edited after signing to authorise "{network}"')
def given_tampered(context, network):
    context.tamper = lambda document: document["scope"].update(networks=[network])


@given("the scope was signed by a key the scanner does not trust")
def given_untrusted_signer(context):
    context.signer = Ed25519PrivateKey.generate()


@given("there is no scope file")
def given_no_file(context):
    context.no_file = True


# ---------- When ----------

@when('I ask to scan "{target}"')
def when_scan(context, target):
    try:
        PortScanner(build_guard(context)).scan_target(target)
    except ScopeError as error:
        context.error = error


@when('I ask the guard about "{target}"')
def when_guard(context, target):
    try:
        build_guard(context).authorise(target)
    except ScopeError as error:
        context.error = error


@when("I load the scope")
def when_load(context):
    try:
        build_guard(context)
    except ScopeError as error:
        context.error = error


# ---------- Then ----------

@then("the target is accepted")
def then_accepted(context):
    assert context.error is None, f"refused: {context.error}"


@then('the scan is refused with reason "{reason}"')
def then_refused(context, reason):
    assert context.error is not None, "the scan was not refused"
    assert context.error.code == reason, f"expected {reason}, got {context.error.code}"


@then('loading the scope fails with reason "{reason}"')
def then_load_fails(context, reason):
    then_refused(context, reason)


@then("no scan engine was started")
def then_no_engine(context):
    assert context.spy.created == 0, f"the engine was started {context.spy.created} time(s)"
    assert context.spy.scans == []


@then("one scan engine was started")
def then_one_engine(context):
    assert context.spy.created == 1, f"the engine was started {context.spy.created} time(s)"


@then("the refusal is recorded in the audit log")
def then_audited(context):
    last = context.guard.audit[-1]
    assert last["decision"] == "REFUSED" and last["code"] == context.error.code, last