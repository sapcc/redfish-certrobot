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
import os
from urllib.parse import urljoin
import requests
import tenacity
import sushy
import subprocess
import openstack

LOG = logging.getLogger(__name__)

VAULT_ADDR = os.getenv("VAULT_ADDR", "https://vault.global.cloud.sap")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
VAULT_REGION = os.getenv("VAULT_REGION")
VAULT_PROJECT = os.getenv("VAULT_PROJECT")
VAULT_ENV = os.getenv("VAULT_ENV", "foundation-secrets")  

if not VAULT_REGION or not VAULT_PROJECT:
    raise RuntimeError("VAULT_REGION and VAULT_PROJECT environment variables must be set")

VAULT_SECRET_PATH = f"{VAULT_ENV}/data/{VAULT_REGION}/{VAULT_PROJECT}/ipmi-user/ironic"

NETBOX_URL = os.getenv("NETBOX_URL", "https://netbox.global.cloud.sap")

GRAPHQL_QUERY = """
query {
  device_list(filters: {
    status: "active",
    tag: "server",
    tenant_group_id: "3",
    tenant_id: "1"
  }) {
    name
    site {
      name
    }
    oob_ip {
      address
    }
  }
}
"""

def get_bmc_creds_from_vault():
    username = os.getenv("BMC_USERNAME")
    password = os.getenv("BMC_PASSWORD")

    if not username:
        LOG.error("Missing BMC_USERNAME in environment.")
        raise RuntimeError("Missing BMC_USERNAME")

    if not password:
        LOG.error("Missing BMC_PASSWORD in environment.")
        raise RuntimeError("Missing BMC_PASSWORD")

    LOG.info("Successfully retrieved BMC credentials.")
    return username, password

def get_devices_from_netbox():
    url = urljoin(NETBOX_URL, "/graphql/")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    response = requests.post(url, json={"query": GRAPHQL_QUERY}, headers=headers)
    response.raise_for_status()

    data = response.json()
    if not data.get("data") or not data["data"].get("device_list"):
        raise ValueError("No devices data found in NetBox response")
    return data["data"]["device_list"]

def nodes():
    vault_username, vault_password = get_bmc_creds_from_vault()
    devices = get_devices_from_netbox()

    for dev in devices:
        name = dev.get("name")
        oob_ip_info = dev.get("oob_ip")

        if not oob_ip_info or not oob_ip_info.get("address"):
            LOG.warning("Skipping device %s: no OOB IP in NetBox", name)
            continue

        yield name, oob_ip_info["address"], vault_username, vault_password


@tenacity.retry(wait=tenacity.wait_fixed(0.5), stop=tenacity.stop_after_attempt(10), reraise=True)
def sushy_client(address, auth):
    url = f"https://{address}/redfish/v1/"
    return sushy.Sushy(url, auth=auth, verify=False)