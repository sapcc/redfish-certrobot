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
from urllib.parse import urljoin, urlparse

import requests
import sushy
import tenacity

import redfish_certrobot
import os
import requests
from urllib.parse import urljoin
from dotenv import load_dotenv
LOG = logging.getLogger(__name__)

load_dotenv()

NETBOX_URL = os.getenv("NETBOX_URL", "https://netbox.global.cloud.sap")
NETBOX_TOKEN = os.getenv("NETBOX_API_TOKEN")

HEADERS = {
    "Authorization": f"Token {NETBOX_TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json",  
}

GRAPHQL_QUERY = """
query {
  device_list(filters: {
    status: "active",
    tag: "server",
    tenant_group_id: "3",
    tenant_id: "1"
  }) {
    name
    primary_ip4 {
      address
    }
  }
}
"""

def get_devices_from_netbox():
    url = urljoin(NETBOX_URL, "/graphql/")

    response = requests.post(url, json={"query": GRAPHQL_QUERY}, headers=HEADERS)
    response.raise_for_status()
    data = response.json()

    if not data.get("data") or not data["data"].get("device_list"):
        raise ValueError("No devices data found in response")
    return data["data"]["device_list"]

def nodes():
    """Yield (ip, username, password) for each node from NetBox."""
    devices = get_devices_from_netbox()

    for dev in devices:
        name = dev.get("name")
        redfish_certrobot.THREAD_LOCAL.address = name

        primary = dev.get("primary_ip4") or dev.get("primary_ip")
        if not primary:
            LOG.warning("Skipping device %s: no primary IP", name)
            continue

        ip = primary["address"].split("/")[0]
        parsed = urlparse(f"https://{ip}")

        # No credentials available from custom fields
        yield name, parsed.netloc, None, None


@tenacity.retry(wait=tenacity.wait_fixed(0.5), stop=tenacity.stop_after_attempt(10), reraise=True)
def sushy_client(address, auth):
    url = f"https://{address}/redfish/v1/"
    return sushy.Sushy(url, auth=auth, verify=False)

if __name__ == "__main__":
    try:
        devices = get_devices_from_netbox()
        print(f"Fetched {len(devices)} devices from NetBox")
    except Exception as e:
        print(f"Error fetching devices: {e}")

    print("Iterating over nodes():")
    try:
        for name, ip, user, pwd in nodes():
            print(f"Node {name}, IP: {ip}, Username: {user}, Password: {pwd}")
    except Exception as e:
        print(f"Error iterating nodes: {e}")
