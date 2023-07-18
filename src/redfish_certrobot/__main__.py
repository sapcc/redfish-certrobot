#!/usr/bin/env python3
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

import logging
import urllib3
from datetime import datetime, timedelta, timezone

import openstack
import sushy
import tenacity

import redfish_certrobot
import redfish_certrobot.issue as issue
import redfish_certrobot.nodes as nodes

_MIN_FIRMWARE_MAJOR_VERSION = {"dell": 5}

LOG = logging.getLogger(__name__)


def _version_check(manufacturer, root):
    min_version = _MIN_FIRMWARE_MAJOR_VERSION.get(manufacturer)
    if not min_version:
        return True

    manager = root.get_manager()
    firmware_version = manager.firmware_version
    if not firmware_version:
        LOG.warning("Skipping due to firmware version not being reported")
        return False

    major_version, _ = firmware_version.split(".", 1)
    major_version = int(major_version)
    if major_version < min_version:
        LOG.warning("Skipping due to outdated BMC firmware version %s (<%s)", firmware_version, min_version)
        return False

    return major_version


def _setup_logging():
    urllib3.disable_warnings()

    old_factory = logging.getLogRecordFactory()

    def _record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        record.address = redfish_certrobot.THREAD_LOCAL.address
        return record

    logging.setLogRecordFactory(_record_factory)

    # Enable logging at DEBUG level
    logging.basicConfig(encoding="utf-8", level=logging.INFO,
        format="%(asctime)s [%(levelname)s] [%(address)s] %(module)s:%(lineno)d: %(message)s",
        datefmt="%Y/%m/%d %H:%M:%S")
    LOG.setLevel(logging.DEBUG)


def main():
    _setup_logging()

    now = datetime.now(timezone.utc)
    max_delta = timedelta(days=7)
    best_before = now - max_delta

    conn = openstack.connect()

    def _dispatch(item):
        address, username, password = item
        redfish_certrobot.THREAD_LOCAL.address = address

        not_valid_after, cert_error = issue.active_cert_valid_until(address, best_before)

        if cert_error == cert_error.CONNECTION_FAILURE:
            LOG.info("Cannot connect to server")
            return None

        if cert_error == cert_error.NO_ERROR:
            LOG.info(f"Has active valid certificate until {not_valid_after}")
            return not_valid_after

        force_renewal = cert_error == cert_error.INVALID_SAN
        with sushy.auth.SessionAuth(username, password) as auth:
            root = nodes.sushy_client(address, auth)

            manufacturer = root.get_system().manufacturer.split()[0].lower()

            if manufacturer == "lenovo":
                # Lenovo issues a CSR with just the hostname in the SAN,
                # which is rejected by our ACME server
                return None

            if manufacturer == "hpe":
                return issue.install_cert_hpe(address, root, best_before)

            version = _version_check(manufacturer, root)
            if not version:
                return None

            cert, cert_content = issue.get_new_cert(address, root, manufacturer,
                                                    best_before, force_renewal=force_renewal)
            if not cert or not cert_content:
                return

            issue.replace_certificate(manufacturer, version, root, cert, cert_content)

    for item in nodes.nodes(conn):
        try:
            _dispatch(item)
        except sushy.exceptions.SushyError as e:
            LOG.error("Cannot issue certificate due to %s", e)


if __name__ == "__main__":
    import sys

    sys.exit(main())
