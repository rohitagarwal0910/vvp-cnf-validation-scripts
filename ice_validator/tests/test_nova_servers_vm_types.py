# -*- coding: utf8 -*-
# ============LICENSE_START=======================================================
# org.onap.vvp/validation-scripts
# ===================================================================
# Copyright © 2018 AT&T Intellectual Property. All rights reserved.
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
import re

from tests import cached_yaml as yaml

from .helpers import validates

from .utils.vm_types import get_vm_types_for_resource
from .utils.vm_types import get_vm_types

from .utils.network_roles import get_network_roles


@validates('R-57282')
def test_vm_type_consistent_on_nova_servers(heat_template):
    '''
    Make sure all nova servers have properly formatted properties
    for their name, image and flavor
    '''
    with open(heat_template) as fh:
        yml = yaml.load(fh)

    # skip if resources are not defined
    if "resources" not in yml:
        pytest.skip("No resources specified in the heat template")

    invalid_nova_servers = []
    for k, v in yml["resources"].items():
        if not isinstance(v, dict):
            continue
        if v.get('type') != 'OS::Nova::Server':
            continue
        if 'properties' not in v:
            continue

        vm_types = get_vm_types_for_resource(v)
        if len(vm_types) != 1:
            invalid_nova_servers.append(k)

    assert not set(invalid_nova_servers), \
        "vm_types not consistant on the following resources {}" \
        .format(invalid_nova_servers)


@validates('R-48067',
           'R-00977')
def test_vm_type_network_role_collision(yaml_file):
    with open(yaml_file) as fh:
        yml = yaml.load(fh)

    # skip if resources are not defined
    if "resources" not in yml:
        pytest.skip("No resources specified in the heat template")

    resources = yml["resources"]

    vm_types = get_vm_types(resources)
    network_roles = get_network_roles(resources)

    collisions = []
    for nr in network_roles:
        for vt in vm_types:
            if vt in nr or nr in vt:
                collisions.append({"vm_type": vt, "network_role": nr})

    assert not collisions, \
        "vm_type and network_role should not be substrings {}" .format(collisions)


@validates('R-50436',
           'R-45188',
           'R-40499')
def test_nova_server_flavor_parameter(yaml_file):

    prop = "flavor"
    check_nova_parameter_format(prop, yaml_file)


@validates('R-51430',
           'R-54171',
           'R-87817')
def test_nova_server_name_parameter(yaml_file):

    prop = "name"
    check_nova_parameter_format(prop, yaml_file)


@validates('R-71152',
           'R-45188',
           'R-57282')
def test_nova_server_image_parameter(yaml_file):

    prop = "image"
    check_nova_parameter_format(prop, yaml_file)


def check_nova_parameter_format(prop, yaml_file):

    formats = {
        "string": {
            "name": re.compile(r'(.+?)_name_\d+$'),
            "flavor": re.compile(r'(.+?)_flavor_name$'),
            "image": re.compile(r'(.+?)_image_name$')
        },
        "comma_delimited_list": {
            "name": re.compile(r'(.+?)_names$')
        }
    }

    with open(yaml_file) as fh:
        yml = yaml.load(fh)

    # skip if resources are not defined
    if "resources" not in yml:
        pytest.skip("No resources specified in the heat template")

    # skip if resources are not defined
    if "parameters" not in yml:
        pytest.skip("No parameters specified in the heat template")

    invalid_parameters = []

    for k, v in yml["resources"].items():
        if not isinstance(v, dict):
            continue
        if v.get('type') != 'OS::Nova::Server':
            continue

        prop_param = v.get("properties", {}) \
                      .get(prop, {}) \
                      .get("get_param")

        if not prop_param:
            pytest.skip("{} doesn't have property {}".format(k, prop))
        elif isinstance(prop_param, list):
            prop_param = prop_param[0]

        template_param_type = yml.get("parameters", {}) \
                                 .get(prop_param, {}) \
                                 .get("type")

        if not template_param_type:
            pytest.skip("could not determine param type for {}".format(prop_param))

        format_match = formats.get(template_param_type, {}) \
                              .get(prop)

        if not format_match or not format_match.match(prop_param):
            invalid_parameters.append(prop_param)

    assert not set(invalid_parameters), \
        "invalid {} parameters detected {}" \
        .format(prop, invalid_parameters)
