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

import collections
import logging
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import openstack
import sushy
import urllib3

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
        try:
            record.address = redfish_certrobot.THREAD_LOCAL.address
        except AttributeError:
            record.address = ""
        return record

    logging.setLogRecordFactory(_record_factory)

    # Enable logging at DEBUG level
    logging.basicConfig(
        encoding="utf-8",
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] [%(address)s] %(module)s:%(lineno)d: %(message)s",
        datefmt="%Y/%m/%d %H:%M:%S",
    )
    LOG.setLevel(logging.DEBUG)


def _summary(results):
    print("Success:")
    errors = 0
    address_by_error = collections.defaultdict(list)
    for address, result in results:
        if isinstance(result, datetime):
            print(f"{address}\t{result}")
        else:
            errors += 1
            address_by_error[result].append(address)

    print("\nFailures:", file=sys.stderr)
    for error, addresses in address_by_error.items():
        print(f"  {error}", file=sys.stderr)
        for address in sorted(addresses):
            print(f"    {address}", file=sys.stderr)

    return errors


def main():
    _setup_logging()

    now = datetime.now(timezone.utc)
    max_delta = timedelta(days=14)
    best_before = now + max_delta

    conn = openstack.connect()

    def _dispatch(item):
        address, username, password = item
        redfish_certrobot.THREAD_LOCAL.address = address

        not_valid_after, cert_error = issue.active_cert_valid_until(address, best_before)

        if cert_error == cert_error.CONNECTION_FAILURE:
            msg = "Cannot connect to server"
            LOG.info("Cannot connect to server")
            return address, msg

        if cert_error == cert_error.NO_ERROR:
            msg = f"Has active valid certificate until {not_valid_after}"
            LOG.info(msg)
            return address, not_valid_after

        force_renewal = cert_error == cert_error.INVALID_SAN
        with sushy.auth.SessionAuth(username, password) as auth:
            root = nodes.sushy_client(address, auth)

            manufacturer = root.get_system().manufacturer.split()[0].lower()

            if manufacturer == "hpe":
                return issue.install_cert_hpe(address, root, best_before)

            version = _version_check(manufacturer, root)
            if not version:
                return address, "Invalid version"

            cert, cert_content = issue.get_new_cert(
                address, root, manufacturer, best_before, force_renewal=force_renewal
            )
            if not cert or not cert_content:
                return address, "Could not issue certificate"

            issue.replace_certificate(manufacturer, version, root, cert, cert_content)
            return address, now  # Not 100% correct, but sufficient

    def _dispatch_logged(item):
        address, *_ = item
        try:
            return _dispatch(item)
        except (
            sushy.exceptions.ConnectionError,
            sushy.exceptions.HTTPError,
            urllib3.exceptions.HTTPError,
            IOError,
        ) as e:
            LOG.error(e)
            return address, type(e).__name__
        except Exception as e:
            import traceback

            LOG.error(traceback.format_exc())
            return address, type(e).__name__

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = executor.map(_dispatch_logged, nodes.nodes(conn))

    return _summary(results)


_original_threading_excepthook = None
_original_sys_excepthook = None


def _threading_excepthook_handler(*args, **kwargs):
    _original_threading_excepthook(*args, **kwargs)
    print(f"{__name__}: unhandled exception in thread", file=sys.stderr, flush=True)
    os._exit(1)


def _sys_excepthook_handler(*args, **kwargs):
    _original_sys_excepthook(*args, **kwargs)
    print(f"{__name__}: unhandled exception in process", file=sys.stderr, flush=True)
    os._exit(1)


if __name__ == "__main__":
    _original_threading_excepthook = threading.excepthook
    threading.excepthook = _threading_excepthook_handler
    _original_sys_excepthook = sys.excepthook
    sys.excepthook = _sys_excepthook_handler
    res = main()
    sys.exit(res)
