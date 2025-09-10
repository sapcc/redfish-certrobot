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
from sys import exit as safe_exit
import sushy

LOG = logging.getLogger(__name__)

NETBOX_URL = os.getenv("NETBOX_URL")
REGION = os.getenv("REGION")

GRAPHQL_QUERY = """
query {
  device_list(filters: {
    status: "active"
    OR: { status: "staged" },
    tag: "server",
    tenant_group_id: "3",
    tenant_id: "1",
    region: "%s"
  }) {
    name
    site {
      name
    }
    oob_ip {
      dns_name
    }
  }
}
""" % (REGION)

def get_bmc_creds_from_env():
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
    if REGION != "":
      response = requests.post(url, json={"query": GRAPHQL_QUERY}, headers=headers)
      response.raise_for_status()
    else:
      LOG.error("No region set, aborting")
      safe_exit(-1)

    data = response.json()
    if not data.get("data") or not data["data"].get("device_list"):
        raise ValueError("No devices data found in NetBox response")
    return data["data"]["device_list"]

def nodes():
    bmc_username, bmc_password = get_bmc_creds_from_env()
    devices = get_devices_from_netbox()

    for dev in devices:
        name = dev.get("name")
        oob_ip_info = dev.get("oob_ip")

        if not oob_ip_info or not oob_ip_info.get("dns_name"):
            LOG.warning("Skipping device %s: no OOB DNS Name in NetBox", name)
            continue

        ip = oob_ip_info["dns_name"]
        yield ip, bmc_username, bmc_password


@tenacity.retry(wait=tenacity.wait_exponential(multiplier=1, min=5, max=30), stop=tenacity.stop_after_attempt(6), reraise=True)
def sushy_client(address, auth):
    url = f"https://{address}/redfish/v1/"
    return sushy.Sushy(url, auth=auth, verify=False)
