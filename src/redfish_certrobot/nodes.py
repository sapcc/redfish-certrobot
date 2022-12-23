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

import openstack
import sushy
import tenacity


def nodes(conn=None, **nodeargs):
    conn = conn or openstack.connect()

    for node in conn.baremetal.nodes(fields=["name", "driver_info"], **nodeargs):
        di = node.driver_info
        username = di["ipmi_username"]
        password = di["ipmi_password"]
        address = di["ipmi_address"]
        # LOG.debug("Checking %s", node.name)
        yield address, username, password


@tenacity.retry(wait=tenacity.wait_fixed(1), stop=tenacity.stop_after_attempt(5))
def sushy_client(address, auth):
    url = f"https://{address}/redfish/v1/"
    return sushy.Sushy(url, auth=auth, verify=False)
