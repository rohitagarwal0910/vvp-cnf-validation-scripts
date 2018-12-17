# -*- coding: utf8 -*-
# ============LICENSE_START====================================================
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

"""structures
"""
import sys


import collections
import inspect
import os
import re

from tests import cached_yaml as yaml
from tests.helpers import load_yaml

from .utils import nested_dict

VERSION = "3.5.0"

# key = pattern, value = regex compiled from pattern
_REGEX_CACHE = {}


def _get_regex(pattern):
    """Return a compiled version of pattern.
    Keep result in _REGEX_CACHE to avoid re-compiling.
    """
    regex = _REGEX_CACHE.get(pattern, None)
    if regex is None:
        regex = re.compile(pattern)
        _REGEX_CACHE[pattern] = regex
    return regex


class HeatObject(object):
    """base class for xxxx::xxxx::xxxx objects
    """

    resource_type = None

    def __init__(self):
        self.re_rids = self.get_re_rids()

    @staticmethod
    def get_re_rids():
        """Return OrderedDict of name: regex
        Each regex parses the proper format for a given rid
        (resource id).
        """
        return collections.OrderedDict()

    def get_rid_match_tuple(self, rid):
        """find the first regex matching `rid` and return the tuple
        (name, match object) or ('', None) if no match.
        """
        for name, regex in self.re_rids.items():
            match = regex.match(rid)
            if match:
                return name, match
        return "", None

    def get_rid_patterns(self):
        """Return OrderedDict of name: friendly regex.pattern
        "friendly" means the group notation is replaced with
        braces, and the trailing "$" is removed.

        NOTE
        nested parentheses in any rid_pattern will break this parser.
        The final character is ASSUMED to be a dollar sign.
        """
        friendly_pattern = _get_regex(r"\(\?P<(.*?)>.*?\)")
        rid_patterns = collections.OrderedDict()
        for name, regex in self.re_rids.items():
            rid_patterns[name] = friendly_pattern.sub(
                r"{\1}", regex.pattern  # replace groups with braces
            )[
                :-1
            ]  # remove trailing $
        return rid_patterns


class ContrailV2NetworkHeatObject(HeatObject):
    """ContrailV2 objects which have network_flavor
    """

    network_flavor_external = "external"
    network_flavor_internal = "internal"
    network_flavor_subint = "subint"

    def get_network_flavor(self, resource):
        """Return the network flavor of resource, one of
        "internal" - get_resource, or get_param contains _int_
        "subint" - get_param contains _subint_
        "external" - otherwise
        None - no parameters found to decide the flavor.

        resource.properties.virtual_network_refs should be a list.
        All the parameters in the list should have the same "flavor"
        so the flavor is determined from the first item.
        """
        network_flavor = None
        network_refs = nested_dict.get(resource, "properties", "virtual_network_refs")
        if network_refs and isinstance(network_refs, list):
            param = network_refs[0]
            if isinstance(param, dict):
                if "get_resource" in param:
                    network_flavor = self.network_flavor_internal
                else:
                    p = param.get("get_param")
                    if isinstance(p, str):
                        if "_int_" in p or p.startswith("int_"):
                            network_flavor = self.network_flavor_internal
                        elif "_subint_" in p:
                            network_flavor = self.network_flavor_subint
                        else:
                            network_flavor = self.network_flavor_external
        return network_flavor


class ContrailV2InstanceIp(ContrailV2NetworkHeatObject):
    """ ContrailV2 InstanceIp
    """

    resource_type = "OS::ContrailV2::InstanceIp"

    def get_re_rids(self):
        """Return OrderedDict of name: regex
        """
        return collections.OrderedDict(
            [
                (
                    "int_ip",
                    _get_regex(
                        r"(?P<vm_type>.+)"
                        r"_(?P<vm_type_index>\d+)"
                        r"_int"
                        r"_(?P<network_role>.+)"
                        r"_vmi"
                        r"_(?P<vmi_index>\d+)"
                        r"_IP"
                        r"_(?P<index>\d+)"
                        r"$"
                    ),
                ),
                (
                    "int_v6_ip",
                    _get_regex(
                        r"(?P<vm_type>.+)"
                        r"_(?P<vm_type_index>\d+)"
                        r"_int"
                        r"_(?P<network_role>.+)"
                        r"_vmi"
                        r"_(?P<vmi_index>\d+)"
                        r"_v6_IP"
                        r"_(?P<index>\d+)"
                        r"$"
                    ),
                ),
                (
                    "subint_ip",
                    _get_regex(
                        r"(?P<vm_type>.+)"
                        r"_(?P<vm_type_index>\d+)"
                        r"_subint"
                        r"_(?P<network_role>.+)"
                        r"_vmi"
                        r"_(?P<vmi_index>\d+)"
                        r"_IP"
                        r"_(?P<index>\d+)"
                        r"$"
                    ),
                ),
                (
                    "subint_v6_ip",
                    _get_regex(
                        r"(?P<vm_type>.+)"
                        r"_(?P<vm_type_index>\d+)"
                        r"_subint"
                        r"_(?P<network_role>.+)"
                        r"_vmi"
                        r"_(?P<vmi_index>\d+)"
                        r"_v6_IP"
                        r"_(?P<index>\d+)"
                        r"$"
                    ),
                ),
                (
                    "ip",
                    _get_regex(
                        r"(?P<vm_type>.+)"
                        r"_(?P<vm_type_index>\d+)"
                        r"_(?P<network_role>.+)"
                        r"_vmi"
                        r"_(?P<vmi_index>\d+)"
                        r"_IP"
                        r"_(?P<index>\d+)"
                        r"$"
                    ),
                ),
                (
                    "v6_ip",
                    _get_regex(
                        r"(?P<vm_type>.+)"
                        r"_(?P<vm_type_index>\d+)"
                        r"_(?P<network_role>.+)"
                        r"_vmi"
                        r"_(?P<vmi_index>\d+)"
                        r"_v6_IP"
                        r"_(?P<index>\d+)"
                        r"$"
                    ),
                ),
            ]
        )


class ContrailV2InterfaceRouteTable(HeatObject):
    """ ContrailV2 InterfaceRouteTable
    """

    resource_type = "OS::ContrailV2::InterfaceRouteTable"


class ContrailV2NetworkIpam(HeatObject):
    """ ContrailV2 NetworkIpam
    """

    resource_type = "OS::ContrailV2::NetworkIpam"


class ContrailV2PortTuple(HeatObject):
    """ ContrailV2 PortTuple
    """

    resource_type = "OS::ContrailV2::PortTuple"


class ContrailV2ServiceHealthCheck(HeatObject):
    """ ContrailV2 ServiceHealthCheck
    """

    resource_type = "OS::ContrailV2::ServiceHealthCheck"


class ContrailV2ServiceInstance(HeatObject):
    """ ContrailV2 ServiceInstance
    """

    resource_type = "OS::ContrailV2::ServiceInstance"


class ContrailV2ServiceInstanceIp(HeatObject):
    """ ContrailV2 ServiceInstanceIp
    """

    resource_type = "OS::ContrailV2::ServiceInstanceIp"


class ContrailV2ServiceTemplate(HeatObject):
    """ ContrailV2 ServiceTemplate
    """

    resource_type = "OS::ContrailV2::ServiceTemplate"


class ContrailV2VirtualMachineInterface(ContrailV2NetworkHeatObject):
    """ ContrailV2 Virtual Machine Interface resource
    """

    resource_type = "OS::ContrailV2::VirtualMachineInterface"

    def get_re_rids(self):
        """Return OrderedDict of name: regex
        """
        return collections.OrderedDict(
            [
                (
                    "vmi_internal",
                    _get_regex(
                        r"(?P<vm_type>.+)"
                        r"_(?P<vm_type_index>\d+)"
                        r"_int"
                        r"_(?P<network_role>.+)"
                        r"_vmi"
                        r"_(?P<vmi_index>\d+)"
                        r"$"
                    ),
                ),
                (
                    "vmi_subint",
                    _get_regex(
                        r"(?P<vm_type>.+)"
                        r"_(?P<vm_type_index>\d+)"
                        r"_subint"
                        r"_(?P<network_role>.+)"
                        r"_vmi"
                        r"_(?P<vmi_index>\d+)"
                        r"$"
                    ),
                ),
                (
                    "vmi_external",
                    _get_regex(
                        r"(?P<vm_type>.+)"
                        r"_(?P<vm_type_index>\d+)"
                        r"_(?P<network_role>.+)"
                        r"_vmi"
                        r"_(?P<vmi_index>\d+)"
                        r"$"
                    ),
                ),
            ]
        )


class ContrailV2VirtualNetwork(HeatObject):
    """ ContrailV2 VirtualNetwork
    """

    resource_type = "OS::ContrailV2::VirtualNetwork"

    def get_re_rids(self):
        """Return OrderedDict of name: regex
        """
        return collections.OrderedDict(
            [
                (
                    "network",
                    _get_regex(r"int" r"_(?P<network_role>.+)" r"_network" r"$"),
                ),
                ("rvn", _get_regex(r"int" r"_(?P<network_role>.+)" r"_RVN" r"$")),
            ]
        )


class NeutronNet(HeatObject):
    """ Neutron Net resource
    """

    resource_type = "OS::Neutron::Net"

    def get_re_rids(self):
        """Return OrderedDict of name: regex
        """
        return collections.OrderedDict(
            [("network", _get_regex(r"int" r"_(?P<network_role>.+)" r"_network" r"$"))]
        )


class NeutronPort(HeatObject):
    """ Neutron Port resource
    """

    resource_type = "OS::Neutron::Port"

    def get_re_rids(self):
        """Return OrderedDict of name: regex
        """
        return collections.OrderedDict(
            [
                (
                    "internal_port",
                    _get_regex(
                        r"(?P<vm_type>.+)"
                        r"_(?P<vm_type_index>\d+)"
                        r"_int"
                        r"_(?P<network_role>.+)"
                        r"_port_(?P<port_index>\d+)"
                        r"$"
                    ),
                ),
                (
                    "port",
                    _get_regex(
                        r"(?P<vm_type>.+)"
                        r"_(?P<vm_type_index>\d+)"
                        r"_(?P<network_role>.+)"
                        r"_port_(?P<port_index>\d+)"
                        r"$"
                    ),
                ),
                (
                    "floating_ip",
                    _get_regex(
                        r"reserve_port"
                        r"_(?P<vm_type>.+)"
                        r"_(?P<network_role>.+)"
                        r"_floating_ip_(?P<index>\d+)"
                        r"$"
                    ),
                ),
                (
                    "floating_v6_ip",
                    _get_regex(
                        r"reserve_port"
                        r"_(?P<vm_type>.+)"
                        r"_(?P<network_role>.+)"
                        r"_floating_v6_ip_(?P<index>\d+)"
                        r"$"
                    ),
                ),
            ]
        )


class NovaServer(HeatObject):
    """ Nova Server resource
    """

    resource_type = "OS::Nova::Server"

    def get_re_rids(self):
        """Return OrderedDict of name: regex
        """
        return collections.OrderedDict(
            [
                (
                    "server",
                    _get_regex(
                        r"(?P<vm_type>.+)" r"_server_(?P<vm_type_index>\d+)" r"$"
                    ),
                )
            ]
        )


class Heat(object):
    """A Heat template.
    filepath - absolute path to template file.
    envpath - absolute path to environmnt file.
    """

    type_cdl = "comma_delimited_list"
    type_num = "number"
    type_str = "string"

    def __init__(self, filepath=None, envpath=None):
        self.filepath = None
        self.basename = None
        self.dirname = None
        self.yml = None
        self.heat_template_version = None
        self.description = None
        self.parameter_groups = None
        self.parameters = None
        self.resources = None
        self.outputs = None
        self.conditions = None
        if filepath:
            self.load(filepath)
        self.env = None
        if envpath:
            self.load_env(envpath)
        self.heat_objects = self.get_heat_objects()

    @property
    def contrail_resources(self):
        """This attribute is a dict of Contrail resources.
        """
        return self.get_resource_by_type(
            resource_type=ContrailV2VirtualMachineInterface.resource_type
        )

    @staticmethod
    def get_heat_objects():
        """Return a dict, key is resource_type, value is the
        HeatObject subclass whose resource_type is the key.
        """
        return _HEAT_OBJECTS

    def get_resource_by_type(self, resource_type):
        """Return dict of resources whose type is `resource_type`.
        key is resource_id, value is resource.
        """
        return {
            rid: resource
            for rid, resource in self.resources.items()
            if self.nested_get(resource, "type") == resource_type
        }

    def get_rid_match_tuple(self, rid, resource_type):
        """return get_rid_match_tuple(rid) called on the class
        corresponding to the given resource_type.
        """
        hoc = self.heat_objects.get(resource_type, HeatObject)
        return hoc().get_rid_match_tuple(rid)

    def get_vm_type(self, rid, resource=None):
        """return the vm_type
        """
        if resource is None:
            resource = self
        resource_type = self.nested_get(resource, "type")
        match = self.get_rid_match_tuple(rid, resource_type)[1]
        vm_type = match.groupdict().get("vm_type") if match else None
        return vm_type

    def load(self, filepath):
        """Load the Heat template given a filepath.
        """
        self.filepath = filepath
        self.basename = os.path.basename(self.filepath)
        self.dirname = os.path.dirname(self.filepath)
        with open(self.filepath) as fi:
            self.yml = yaml.load(fi)
        self.heat_template_version = self.yml.get("heat_template_version", None)
        self.description = self.yml.get("description", "")
        self.parameter_groups = self.yml.get("parameter_groups", {})
        self.parameters = self.yml.get("parameters") or {}
        self.resources = self.yml.get("resources", {})
        self.outputs = self.yml.get("outputs", {})
        self.conditions = self.yml.get("conditions", {})

    def get_all_resources(self, base_dir):
        """
        Like ``resources``, but this returns all the resources definitions
        defined in the template, resource groups, and nested YAML files.
        """
        resources = {}
        for r_id, r_data in self.resources.items():
            resources[r_id] = r_data
            resource = Resource(r_id, r_data)
            if resource.is_nested():
                nested = Heat(os.path.join(base_dir, resource.get_nested_filename()))
                resources.update(nested.get_all_resources(base_dir))
        return resources

    def load_env(self, envpath):
        """
        Load the Environment template given a envpath.
        """
        self.env = Env(filepath=envpath)

    @staticmethod
    def nested_get(dic, *keys, **kwargs):
        """make utils.nested_dict.get available as a class method.
        """
        return nested_dict.get(dic, *keys, **kwargs)

    @property
    def neutron_port_resources(self):
        """This attribute is a dict of Neutron Ports
        """
        return self.get_resource_by_type(resource_type=NeutronPort.resource_type)

    @property
    def nova_server_resources(self):
        """This attribute is a dict of Nova Servers
        """
        return self.get_resource_by_type(resource_type=NovaServer.resource_type)

    @staticmethod
    def part_is_in_name(part, name):
        """
        Return True if any of
        - name starts with part + '_'
        - name contains '_' + part + '_'
        - name ends with '_' + part
        False otherwise
        """
        return bool(
            re.search("(^(%(x)s)_)|(_(%(x)s)_)|(_(%(x)s)$)" % dict(x=part), name)
        )


class Env(Heat):
    """An Environment file
    """

    pass


class Resource(object):
    """A Resource
    """

    def __init__(self, resource_id=None, resource=None):
        self.resource_id = resource_id or ""
        self.resource = resource or {}
        self.properties = self.resource.get("properties", {})
        self.resource_type = resource.get("type", "")

    @staticmethod
    def get_index_var(resource):
        """Return the index_var for this resource.
        """
        index_var = nested_dict.get(resource, "properties", "index_var") or "index"
        return index_var

    def get_nested_filename(self):
        """Returns the filename of the nested YAML file if the
        resource is a nested YAML or ResourceDef, returns '' otherwise."""
        typ = self.resource.get("type", "")
        if typ == "OS::Heat::ResourceGroup":
            rd = nested_dict.get(self.resource, "properties", "resource_def")
            typ = rd.get("type", "") if rd else ""
        ext = os.path.splitext(typ)[1]
        ext = ext.lower()
        if ext == ".yml" or ext == ".yaml":
            return typ
        else:
            return ""

    def get_nested_properties(self):
        """
        Returns {} if not nested
        Returns resource: properties if nested
        Returns resource: properties: resource_def: properties if RG
        """
        if not bool(self.get_nested_filename()):
            return {}
        elif self.resource_type == "OS::Heat::ResourceGroup":
            return nested_dict.get(
                self.properties, "resource_def", "properties", default={}
            )
        else:
            return self.properties

    @property
    def depends_on(self):
        """
        Returns the list of resources this resource depends on.  Always
        returns a list.

        :return: list of all resource IDs this resource depends on.  If none,
                 then returns an empty list
        """
        parents = self.resource.get("depends_on", [])
        return parents if isinstance(parents, list) else [parents]

    def is_nested(self):
        """Returns True if the resource represents a Nested YAML resource
        using either type: {filename} or ResourceGroup -> resource_def"""
        return bool(self.get_nested_filename())

    def get_nested_yaml(self, base_dir):
        """If the resource represents a Nested YAML resource, then it
        returns the loaded YAML.  If the resource is not nested or the
        file cannot be found, then an empty dict is returned"""
        filename = self.get_nested_filename()
        if filename:
            file_path = os.path.join(base_dir, filename)
            return load_yaml(file_path) if os.path.exists(file_path) else {}
        else:
            return {}


def _get_heat_objects():
    """
    Introspect this module and return a dict of all HeatObject sub-classes with
    a (True) resource_type. Key is the resource_type, value is the
    corresponding class.
    """
    mod_classes = inspect.getmembers(sys.modules[__name__], inspect.isclass)
    heat_objects = {
        c.resource_type: c
        for _, c in mod_classes
        if issubclass(c, HeatObject) and c.resource_type
    }
    return heat_objects


_HEAT_OBJECTS = _get_heat_objects()
