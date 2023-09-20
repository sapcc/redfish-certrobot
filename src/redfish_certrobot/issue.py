# Copyright 2022 SAP SE
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from contextlib import contextmanager
from enum import Enum
import logging
import os
import pathlib
import subprocess
import ssl
import threading
import typing
from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend


import sushy
import tenacity
from dateutil import parser
from sushy.resources.certificateservice.constants import CertificateType
from sushy.resources.constants import ResetType


ACME_SERVER = os.getenv("ACME_SERVER").strip('"\' \t')
DNS_RESOLVERS = os.getenv("DNS_RESOLVERS").strip('"\' \t')
ISSUER = os.getenv("ISSUER").strip('"\' \t')
CSR_COUNTRY = os.getenv("CSR_COUNTRY").strip('"\' \t')
CSR_STATE = os.getenv("CSR_STATE").strip('"\' \t')
CSR_CITY = os.getenv("CSR_CITY").strip('"\' \t')
CSR_ORGANIZATION = os.getenv("CSR_ORGANIZATION").strip('"\' \t')
CSR_ORGANIZATIONAL_UNIT = os.getenv("CSR_ORGANIZATIONAL_UNIT").strip('"\' \t')
CSR_EMAIL = os.getenv("CSR_EMAIL").strip('"\' \t')

LOG = logging.getLogger(__name__)


def invalid_file(path):
    return not path.exists() or path.stat().st_size == 0


@contextmanager
def _generate_csr(certificate_service, collection, address):
    csr_path = pathlib.Path(f"{address}.csr")
    if invalid_file(csr_path):
        LOG.debug("Generating new CSR")
        generate_csr_element = certificate_service._actions.generate_csr
        target_uri = generate_csr_element.target_uri
        # All those fields are mandatory for Dell iDrac
        data = {
            "CertificateCollection": collection,
            "Country": CSR_COUNTRY,
            "State": CSR_STATE,
            "City": CSR_CITY,
            "CommonName": address,
            "AlternativeNames": [address],
            "Organization": CSR_ORGANIZATION,
            "OrganizationalUnit": CSR_ORGANIZATIONAL_UNIT,
            "Email": CSR_EMAIL,
        }
        with csr_path.open(mode="w", encoding="utf-8") as csr:
            result = certificate_service._conn.post(target_uri, data=data, timeout=30.0)
            data = result.json()
            csr.write(data["CSRString"])
    yield csr_path
    csr_path.unlink(missing_ok=True)


_LEGO_LOCK = threading.BoundedSemaphore(8)  # Just a guess, higher values might work as well


@contextmanager
def _request_cert(csr_path):
    crt_path = pathlib.Path(f".lego/certificates/{csr_path.with_suffix('.crt')}")
    if invalid_file(crt_path):
        LOG.debug("Requesting certificate")
        with _LEGO_LOCK:
            subprocess.run(
                [
                    "lego",
                    "--accept-tos",
                    "--server",
                    ACME_SERVER,
                    "--email",
                    CSR_EMAIL,
                    "--dns",
                    "designate",
                    "--dns.resolvers",
                    DNS_RESOLVERS,
                    "--csr",
                    csr_path,
                    "--cert.timeout",
                    "120",
                    "run",
                ],
                check=True,
            )
    yield crt_path
    crt_path.unlink(missing_ok=True)


def _get_certificate_content(cert_path):
    with cert_path.open(encoding="utf-8") as cert_file:
        return cert_file.read()


def import_ssl_certificate_dell(manager, cert_content):
    url = "Dell/Managers/iDRAC.Embedded.1/DelliDRACCardService/Actions/DelliDRACCardService.ImportSSLCertificate"
    data = {
        "CertificateType": "Server",
        "SSLCertificateFile": cert_content,
    }

    response = manager._conn.post(
        url,
        data=data,
        timeout=30.0,
    )
    data = response.json()
    if response.status_code == 200:
        return True

    LOG.error(
        "FAIL, POST command failed, status code %s returned",
        response.status_code,
    )
    data = response.json()
    LOG.error("POST command failure results:\n%s", data)
    return False


def cert_valid_until(cert, best_before: datetime, address) -> typing.Union[datetime, None]:
    valid_not_after = cert.valid_not_after
    if valid_not_after < best_before:
        LOG.info("Certificate expires soon or is expired")
        return None

    if cert.subject.common_name != address:
        LOG.info("Certificate issued to %s", cert.subject.common_name)
        return None

    if cert.issuer.common_name != ISSUER:
        LOG.info("Certificate issued by %s instead of %s", cert.issuer.common_name, ISSUER)
        return None

    return valid_not_after


def _get_common_name(ssl_cert_name):
    attrs = ssl_cert_name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    if attrs:
        return attrs[0].value
    return None


@tenacity.retry(wait=tenacity.wait_fixed(0.5), stop=tenacity.stop_after_attempt(6), reraise=True)
def get_active_cert(address):
    pem_data = ssl.get_server_certificate((address, 443), timeout=10)
    return x509.load_pem_x509_certificate(pem_data.encode('ascii'), default_backend())


class CertError(Enum):
    NO_ERROR = 0
    TOO_OLD = 1
    INVALID_SUBJECT = 2
    INVALID_ISSUER = 3
    INVALID_SAN = 4
    CONNECTION_FAILURE = 5


def active_cert_valid_until(address, best_before: datetime, cert=None) -> typing.Tuple[datetime, CertError]:
    if not cert:
        try:
            cert = get_active_cert(address)
        except (TimeoutError, ConnectionRefusedError):
            return None, CertError.CONNECTION_FAILURE

    not_valid_after = cert.not_valid_after
    if not_valid_after.tzinfo is None:
        not_valid_after = not_valid_after.replace(tzinfo=best_before.tzinfo)

    if not_valid_after < best_before:
        LOG.info("Active certificate expires soon or is expired")
        return not_valid_after, CertError.TOO_OLD

    if (cn := _get_common_name(cert.subject)) != address:
        LOG.info("Active certificate issued to %s", cn)
        return not_valid_after, CertError.INVALID_SUBJECT

    if (cn := _get_common_name(cert.issuer)) != ISSUER:
        LOG.info("Active certificate issued by %s instead of %s", cn, ISSUER)
        return not_valid_after, CertError.INVALID_ISSUER

    ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if not ext:
        LOG.info("Active certificate does not contain a SAN")
        return not_valid_after, CertError.INVALID_SAN

    san = ext.value.get_values_for_type(x509.DNSName)
    if address not in san:
        LOG.info("Active certificate does not contain host as SAN %s", san)
        return not_valid_after, CertError.INVALID_SAN

    return not_valid_after, CertError.NO_ERROR


@tenacity.retry(wait=tenacity.wait_fixed(1), stop=tenacity.stop_after_attempt(60))
def _fetch_csr_hpe(manager):
    client = manager._conn
    target_uri = f"{manager.path}/SecurityService/HttpsCert/"
    response = client.get(target_uri)
    data = response.json()
    return data["CertificateSigningRequest"]


@contextmanager
def _generate_csr_hpe(manager, address):
    client = manager._conn
    csr_path = pathlib.Path(f"{address}.csr")
    target_uri = f"{manager.path}/SecurityService/HttpsCert/Actions/HpeHttpsCert.GenerateCSR/"

    if invalid_file(csr_path):
        LOG.debug("Generating new CSR")
        data = {
            "City": "Walldorf",
            "CommonName": address,
            "Country": "DE",
            "IncludeIP": True,
            "OrgName": "SAP",
            "OrgUnit": "CC",
            "State": "BW",
        }
        with csr_path.open(mode="w", encoding="utf-8") as csr_file:
            result = client.post(target_uri, data=data)
            data = result.json()
            try:
                csr_content = data["Certificate"]
            except KeyError:
                csr_content = _fetch_csr_hpe(manager)
            csr_file.write(csr_content)

    yield csr_path
    csr_path.unlink(missing_ok=True)


def import_ssl_certificate_hpe(manager, cert_content):
    client = manager._conn
    target_uri = f"{manager.path}/SecurityService/HttpsCert/Actions/HpeHttpsCert.ImportCertificate/"
    data = {
        "Certificate": cert_content,
    }

    response = client.post(target_uri, data=data)
    return response.status_code == 200


@dataclass
class Identifier:
    common_name: str
    city: str | None = None
    country: str | None = None
    email: str | None = None
    organization: str | None = None
    organizational_unit: str | None = None
    state: str | None = None


_X509_TO_IDENTIFIER_FIELD = {
    "CN": "common_name",
    "OU": "organizational_unit",
    "O": "organization",
    "L": "city",
    "S": "state",
    "C": "country",
}


def _parse_identifier_hpe(item: str) -> Identifier:
    import re

    parsed = {}
    for key, value in re.findall(r"([^= ]*)\s*=\s*([^,]*)", item):
        field_name = _X509_TO_IDENTIFIER_FIELD.get(key)
        if field_name:
            parsed[field_name] = value
    return Identifier(**parsed)


@dataclass
class HpeHttpsCert:
    issuer: Identifier
    serial_number: str
    subject: Identifier
    valid_not_after: datetime
    valid_not_before: datetime


def get_current_cert_hpe(manager):
    client = manager._conn
    target_uri = f"{manager.path}/SecurityService/HttpsCert/"
    response = client.get(target_uri)
    data = response.json()
    cert_info = data["X509CertificateInformation"]
    issuer = _parse_identifier_hpe(cert_info["Issuer"])
    subject = _parse_identifier_hpe(cert_info["Subject"])
    return HpeHttpsCert(
        issuer=issuer,
        subject=subject,
        serial_number=cert_info["SerialNumber"],
        valid_not_after=parser.parse(cert_info["ValidNotAfter"]),
        valid_not_before=parser.parse(cert_info["ValidNotBefore"]),
    )


def install_cert_hpe(address, root, best_before):
    manager = root.get_manager()

    cert = get_current_cert_hpe(manager)
    if cert_valid_until(cert, best_before, address):
        return

    with _generate_csr_hpe(manager, address) as csr_path:
        with _request_cert(csr_path) as cert_path:
            cert_content = _get_certificate_content(cert_path)

    if import_ssl_certificate_hpe(manager, cert_content):
        manager.reset_manager(ResetType.GRACEFUL_RESTART)


def _find_manager_cert(root, manufacturer):
    try:
        manager = root.get_manager()
        try:
            certificate_service = root.get_certificate_service()
        except sushy.exceptions.MissingAttributeError:
            firmware_version = manager.firmware_version
            LOG.warning("Certificate Service not found. Firmware Version: %s %s", manufacturer, firmware_version)
            return None, None

        certificate_locations = certificate_service.certificate_locations

        for cert in certificate_locations.get_members():
            if cert.path.startswith(manager.path):
                return certificate_service, cert

        LOG.warning("Certificate for Manager not found")
        return certificate_service, None
    except sushy.exceptions.ServerSideError:
        return None, None


def get_new_cert(address, root, manufacturer, best_before, force_renewal=False):
    certificate_service, cert = _find_manager_cert(root, manufacturer)
    if not cert:
        return None, None

    if not force_renewal and cert_valid_until(cert, best_before, address):
        return cert, None

    if manufacturer == "cisco":
        collection = cert.path
    else:  # Hopefully
        collection = {"@odata.id": cert.path.rsplit("/", 1)[0]}

    with _generate_csr(certificate_service, collection, address) as csr_path:
        with _request_cert(csr_path) as cert_path:
            return cert, _get_certificate_content(cert_path)


def replace_certificate_dell(major_version, root, cert_content):
    manager = root.get_manager()
    imported = import_ssl_certificate_dell(manager, cert_content)
    if imported:
        if major_version < 6:
            manager.reset_manager(ResetType.GRACEFUL_RESTART)
        return True
    return False


def replace_certificate(manufacturer, version, root, cert, cert_content):
    if manufacturer == "dell":
        return replace_certificate_dell(version, root, cert_content)

    certificate_service = root.get_certificate_service()
    certificate_service.replace_certificate(cert.path, cert_content, CertificateType.PEM)
