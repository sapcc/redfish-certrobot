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
from dotenv import load_dotenv
import sushy
import subprocess
import openstack

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)

c1, c2=0,0
no_ip_devices=[]

load_dotenv()

VAULT_ADDR = os.getenv("VAULT_ADDR", "https://vault.global.cloud.sap")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
VAULT_SECRET_PATH = "foundation-secrets/data/qa-de-1/ironic/ipmi-user/ironic"  

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
    if not VAULT_TOKEN:
        raise RuntimeError("Vault token not found. Please set VAULT_TOKEN environment variable.")

    url = f"{VAULT_ADDR}/v1/{VAULT_SECRET_PATH}"
    headers = {"X-Vault-Token": VAULT_TOKEN}
    LOG.debug(f"Fetching BMC creds from Vault at {url}")

    response = requests.get(url, headers=headers)
    response.raise_for_status()

    secret_data = response.json().get("data", {}).get("data", {})
    username = secret_data.get("username")
    password = secret_data.get("password")

    if not username or not password:
        raise ValueError("BMC credentials not found in Vault response")

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
    
    global c1, c2, no_ip_devices
    vault_username, vault_password = get_bmc_creds_from_vault()

    devices = get_devices_from_netbox()
    vault_username, vault_password = get_bmc_creds_from_vault()

    for dev in devices:
        name = dev.get("name")
        oob_ip_info = dev.get("oob_ip")

        if not oob_ip_info or not oob_ip_info.get("address"):
            no_ip_devices.append(name)
            c1+=1
            LOG.warning("Skipping device %s: no OOB IP in NetBox", name)
            continue

        yield name, oob_ip_info["address"], vault_username, vault_password


@tenacity.retry(wait=tenacity.wait_fixed(0.5), stop=tenacity.stop_after_attempt(10), reraise=True)
def sushy_client(address, auth):
    url = f"https://{address}/redfish/v1/"
    return sushy.Sushy(url, auth=auth, verify=False)