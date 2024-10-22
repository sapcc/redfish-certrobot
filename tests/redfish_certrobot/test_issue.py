from datetime import datetime, timezone
from redfish_certrobot import issue

ADDRESS = "address"
ISSUER = "issuer"
CERT_EXPIRY_UTC = datetime(year=2000, month=1, day=15, tzinfo=timezone.utc)
AFTER_EXPIRY_UTC = datetime(year=2000, month=1, day=16, tzinfo=timezone.utc)
BEFORE_EXPIRY_UTC = datetime(year=2000, month=1, day=14, tzinfo=timezone.utc)


def _test_active_cert_valid_until(mocker, best_before_utc=BEFORE_EXPIRY_UTC, subject=ADDRESS, issuer=ISSUER, **kwargs):
    mock_cert = mocker.Mock(not_valid_after_utc=CERT_EXPIRY_UTC, subject=subject, issuer=issuer, **kwargs)
    mocker.patch("redfish_certrobot.issue.get_active_cert").return_value = mock_cert
    mocker.patch("redfish_certrobot.issue._get_common_name").side_effect = lambda x: x
    return issue.active_cert_valid_until(ADDRESS, best_before_utc)


def test_connection_failure(mocker):
    mocker.patch("redfish_certrobot.issue.get_active_cert").side_effect = ConnectionRefusedError()
    not_valid_after_utc, cert_error = issue.active_cert_valid_until(ADDRESS, None)
    assert not_valid_after_utc is None
    assert cert_error == cert_error.CONNECTION_FAILURE


def test_connection_timeout(mocker):
    mocker.patch("redfish_certrobot.issue.get_active_cert").side_effect = TimeoutError()
    not_valid_after_utc, cert_error = issue.active_cert_valid_until(ADDRESS, None)
    assert not_valid_after_utc is None
    assert cert_error == cert_error.CONNECTION_FAILURE


def test_cert_expired(mocker):
    assert AFTER_EXPIRY_UTC > CERT_EXPIRY_UTC
    not_valid_after_utc, cert_error = _test_active_cert_valid_until(mocker, best_before_utc=AFTER_EXPIRY_UTC)
    assert cert_error == cert_error.TOO_OLD


def test_cert_invalid_subject(mocker):
    assert BEFORE_EXPIRY_UTC < CERT_EXPIRY_UTC
    not_valid_after_utc, cert_error = _test_active_cert_valid_until(mocker, subject="other")
    assert cert_error == cert_error.INVALID_SUBJECT


def test_cert_invalid_issuer(mocker):
    assert BEFORE_EXPIRY_UTC < CERT_EXPIRY_UTC
    not_valid_after_utc, cert_error = _test_active_cert_valid_until(mocker, issuer="other")
    assert cert_error == cert_error.INVALID_ISSUER


def test_cert_invalid_san(mocker):
    assert BEFORE_EXPIRY_UTC < CERT_EXPIRY_UTC
    not_valid_after_utc, cert_error = _test_active_cert_valid_until(mocker, issuer="other")
    assert cert_error == cert_error.INVALID_ISSUER
