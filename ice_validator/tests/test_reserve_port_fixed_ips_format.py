# -*- coding: utf8 -*-
# ============LICENSE_START=======================================================
# org.onap.vvp/validation-scripts
# ===================================================================
# Copyright © 2017 AT&T Intellectual Property. All rights reserved.
# ===================================================================
#
# Unless otherwise specified, all software contained herein is licensed
# under the Apache License, Version 2.0 (the "License");
# you may not use this software except in compliance with the License.
# You may obtain a copy of the License at
#
#             http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
#
# Unless otherwise specified, all documentation contained herein is licensed
# under the Creative Commons License, Attribution 4.0 Intl. (the "License");
# you may not use this documentation except in compliance with the License.
# You may obtain a copy of the License at
#
#             https://creativecommons.org/licenses/by/4.0/
#
# Unless required by applicable law or agreed to in writing, documentation
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# ============LICENSE_END============================================
#
# ECOMP is a trademark and service mark of AT&T Intellectual Property.
#

import pytest
import yaml
from .utils.network_roles import get_network_role_from_port
from .utils.ports import is_reserved_port
import re


def test_reserve_port_fixed_ips_format(heat_template):
    '''
    Make sure all fixed_ips properties for a reserved port
    follow the allowed naming conventions
    '''
    allowed_formats = [
                      ["fixed_ips", "string", "internal",
                       re.compile(r'(.+?)_int_(.+?)_floating_v6_ip')],
                      ["fixed_ips", "string", "internal",
                       re.compile(r'(.+?)_int_(.+?)_floating_ip')],
                      ["fixed_ips", "string", "external",
                       re.compile(r'(.+?)_floating_v6_ip')],
                      ["fixed_ips", "string", "external",
                       re.compile(r'(.+?)_floating_ip')],
                      ]

    with open(heat_template) as fh:
        yml = yaml.load(fh)

    # skip if resources are not defined
    if "resources" not in yml:
        pytest.skip("No resources specified in the heat template")

    # check both valid and invalid patterns to catch edge cases
    invalid_fixed_ips = []

    for k1, v1 in yml["resources"].items():
        if not isinstance(v1, dict):
            continue
        if "properties" not in v1:
            continue
        if v1.get("type") != "OS::Neutron::Port":
            continue
        if not is_reserved_port(k1):
            continue

        network_role = get_network_role_from_port(v1)

        for k2, v2 in v1["properties"].items():
            if k2 != "fixed_ips":
                continue
            for v3 in v2:
                if "ip_address" not in v3:
                    continue
                if "get_param" not in v3["ip_address"]:
                    continue

                valid_fixed_ip = False
                for v4 in allowed_formats:
                    param = v3["ip_address"]["get_param"]
                    if isinstance(param, list):
                        param = param[0]

                    # check if pattern matches
                    m = v4[3].match(param)
                    if m:
                        if v4[2] == "internal" and\
                            len(m.groups()) > 1 and\
                                m.group(2) == network_role:
                                valid_fixed_ip = True
                                break
                        elif v4[2] == "external" and\
                                len(m.groups()) > 0 and\
                                m.group(1).endswith("_" + network_role):
                                    valid_fixed_ip = True
                                    break

                if not valid_fixed_ip:
                    invalid_fixed_ips.append(param)

    assert not set(invalid_fixed_ips)
