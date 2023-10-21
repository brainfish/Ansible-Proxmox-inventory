#!/usr/bin/env python3

# Copyright (C) 2014  Mathieu GAUTHIER-LAFAYE <gauthierl@lapth.cnrs.fr>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Updated 2016 by Matt Harris <matthaeus.harris@gmail.com>
#
# Added support for Proxmox VE 4.x
# Added support for using the Notes field of a VM to define groups and variables:
# A well-formatted JSON object in the Notes field will be added to the _meta
# section for that VM.  In addition, the "groups" key of this JSON object may be
# used to specify group membership:
#
# { "groups": ["utility", "databases"], "a": false, "b": true }

from six.moves.urllib import request, parse, error

try:
    import json
except ImportError:
    import simplejson as json
import os
import sys
import socket
import re
from functools import cache
from optparse import OptionParser

from six import iteritems

from six.moves.urllib.error import HTTPError

from ansible.module_utils.urls import open_url


class ProxmoxNodeList(list):
    def get_names(self):
        return [node['node'] for node in self]


class ProxmoxVM(dict):
    def get_variables(self):
        variables = {}
        for key, value in iteritems(self):
            variables['proxmox_' + key] = value
        return variables


class ProxmoxVMList(list):
    def __init__(self, data=[], pxmxver=0.0):
        self.ver = pxmxver
        for item in data:
            self.append(ProxmoxVM(item))

    def get_names(self):
        if self.ver >= 4.0:
            return [vm['name'] for vm in self if 'template' in vm and vm['template'] != 1]
        else:
            return [vm['name'] for vm in self]

    def get_by_name(self, name):
        results = [vm for vm in self if vm['name'] == name]
        return results[0] if len(results) > 0 else None

    def get_variables(self):
        variables = {}
        for vm in self:
            variables[vm['name']] = vm.get_variables()

        return variables


class ProxmoxPoolList(list):
    def get_names(self):
        return [pool['poolid'] for pool in self]


class ProxmoxVersion(dict):
    def get_version(self):
        return float(self['version'].split('.')[0])


class ProxmoxPool(dict):
    def get_members_name(self):
        return [member['name'] for member in self['members'] if (member['type'] == 'qemu' or member['type'] == 'lxc') and member['template'] != 1]


class ProxmoxAPI(object):
    def __init__(self, options, config_path):
        self.options = options
        self.credentials = None

        if not options.url or not options.username or not options.password:
            if os.path.isfile(config_path):
                with open(config_path, "r") as config_file:
                    config_data = json.load(config_file)
                    if not options.url:
                        try:
                            options.url = config_data["url"]
                        except KeyError:
                            options.url = None
                    if not options.username:
                        try:
                            options.username = config_data["username"]
                        except KeyError:
                            options.username = None
                    if not options.password:
                        try:
                            options.password = config_data["password"]
                        except KeyError:
                            options.password = None
                    if not options.token:
                        try:
                            options.token = config_data["token"]
                        except KeyError:
                            options.token = None
                    if not options.secret:
                        try:
                            options.secret = config_data["secret"]
                        except KeyError:
                            options.secret = None
                    if not options.include:
                        try:
                            options.include = config_data["include"]
                        except KeyError:
                            options.include = []
                    if not options.exclude:
                        try:
                            options.exclude = config_data["exclude"]
                        except KeyError:
                            options.exclude = []
                    if not options.include_ips:
                        try:
                            options.include_ips = config_data["include_ips"]
                        except KeyError:
                            options.include_ips = []
                    if not options.exclude_ips:
                        try:
                            options.exclude_ips = config_data["exclude_ips"]
                        except KeyError:
                            options.exclude_ips = []
                    if not options.include_cidr:
                        try:
                            options.include_cidr = config_data["include_cidr"]
                        except KeyError:
                            options.include_cidr = []
                    if not options.exclude_cidr:
                        try:
                            options.exclude_cidr = config_data["exclude_cidr"]
                        except KeyError:
                            options.exclude_cidr = []
                    if not options.include_ipv6:
                        try:
                            options.include_ipv6 = config_data["include_ipv6"]
                        except KeyError:
                            options.include_ipv6 = False

        if not options.url:
            raise Exception('Missing mandatory parameter --url (or PROXMOX_URL or "url" key in config file).')
        elif not options.username:
            raise Exception(
                'Missing mandatory parameter --username (or PROXMOX_USERNAME or "username" key in config file).')
        elif not options.password and (not options.token or not options.secret):
            raise Exception(
                'Missing mandatory parameter --password (or PROXMOX_PASSWORD or "password" key in config file) or alternatively --token and --secret (or PROXMOX_TOKEN and PROXMOX_SECRET or "token" and "secret" key in config file).')

        # URL should end with a trailing slash
        if not options.url.endswith("/"):
            options.url = options.url + "/"

    def auth(self):
        if not self.options.token or not self.options.secret:
            request_path = '{0}api2/json/access/ticket'.format(self.options.url)

            request_params = parse.urlencode({
                'username': self.options.username,
                'password': self.options.password,
            })

            data = json.load(open_url(request_path, data=request_params,
                                    validate_certs=self.options.validate))

            self.credentials = {
                'ticket': data['data']['ticket'],
                'CSRFPreventionToken': data['data']['CSRFPreventionToken'],
            }

    @cache
    def get(self, url, data=None):
        request_path = '{0}{1}'.format(self.options.url, url)

        headers = {}
        if not self.options.token or not self.options.secret:
            headers['Cookie'] = 'PVEAuthCookie={0}'.format(self.credentials['ticket'])
        else:
            headers['Authorization'] = 'PVEAPIToken={0}!{1}={2}'.format(self.options.username, self.options.token, self.options.secret)
        
        request = open_url(request_path, data=data, headers=headers,
                           validate_certs=self.options.validate)

        response = json.load(request)
        return response['data']

    def nodes(self):
        return ProxmoxNodeList(self.get('api2/json/nodes'))

    def vms_by_type(self, node, type):
        return ProxmoxVMList(self.get('api2/json/nodes/{0}/{1}'.format(node, type)), self.version().get_version())

    def vm_description_by_type(self, node, vm, type):
        return self.get('api2/json/nodes/{0}/{1}/{2}/config'.format(node, type, vm))

    def node_qemu(self, node):
        return self.vms_by_type(node, 'qemu')

    def node_qemu_description(self, node, vm):
        return self.vm_description_by_type(node, vm, 'qemu')

    def node_lxc(self, node):
        return self.vms_by_type(node, 'lxc')

    def node_lxc_description(self, node, vm):
        return self.vm_description_by_type(node, vm, 'lxc')

    def node_openvz(self, node):
        return self.vms_by_type(node, 'openvz')

    def node_openvz_description(self, node, vm):
        return self.vm_description_by_type(node, vm, 'openvz')

    def pools(self):
        return ProxmoxPoolList(self.get('api2/json/pools'))

    def pool(self, poolid):
        return ProxmoxPool(self.get('api2/json/pools/{0}'.format(poolid)))
    
    def qemu_agent(self, node, vm):
        try:
            info = self.get('api2/json/nodes/{0}/qemu/{1}/agent/info'.format(node, vm))
            if info is not None:
                return True
        except HTTPError as error:
            return False

    # Get an LXC's IP address
    def openvz_ip_address(self, node, vm):
        try:
            config = self.get('api2/json/nodes/{0}/lxc/{1}/config'.format(node, vm))
        except HTTPError:
            return False
        
        found_ip_address = False
        net_num = 0
        while 'net{0}'.format(net_num) in config:
            net_key = 'net{0}'.format(net_num)
            try:
                interface_name = re.search('name=([^,]+)', config[net_key]).group(1)
                ip_address = re.search('ip=([^,/]+)', config[net_key]).group(1)
                if self.include_interface_name(interface_name) and self.include_ip_address(ip_address):
                    found_ip_address = ip_address
            except AttributeError:
                pass
            net_num += 1
        return found_ip_address

    def lxc_hostname(self, node, vm):
        try:
            config = self.get('api2/json/nodes/{0}/lxc/{1}/config'.format(node, vm))
        except HTTPError:
            return False
        
        try:
            hostname = config['hostname']
            return hostname
        except:
            return False
    
    def version(self):
        return ProxmoxVersion(self.get('api2/json/version'))

    def qemu_agent_info(self, node, vm):
        system_info = SystemInfo()
        osinfo = self.get('api2/json/nodes/{0}/qemu/{1}/agent/get-osinfo'.format(node, vm))['result']
        if osinfo:
            if 'id' in osinfo:
                system_info.id = osinfo['id']

            if 'name' in osinfo:
                system_info.name = osinfo['name']

            if 'machine' in osinfo:
                system_info.machine = osinfo['machine']

            if 'kernel-release' in osinfo:
                system_info.kernel = osinfo['kernel-release']

            if 'version-id' in osinfo:
                system_info.version_id = osinfo['version-id']

        ip_address = None
        networks = self.get('api2/json/nodes/{0}/qemu/{1}/agent/network-get-interfaces'.format(node, vm))['result']
        
        if networks:
            if type(networks) is dict:
                for network in networks:
                    if self.valid_network_interface(network):
                        #TODO repro this case because it shouldn't work with the preexisting code
                        for ip_address in network['ip-address']:
                            try:
                                # IP address validation
                                if ip_address['ip-address'] != '127.0.0.1' and socket.inet_aton(ip_address['ip-address']):
                                    system_info.ip_address = ip_address
                            except socket.error:
                                pass
            elif type(networks) is list:
                for network in networks:
                    if self.valid_network_interface(network):
                        for ip_address in network['ip-addresses']:
                            if self.include_ip_address(ip_address['ip-address']):
                                system_info.ip_address = ip_address['ip-address']

        return system_info

    def valid_network_interface(self, network):
        if 'ip-addresses' not in network:
            return False
    
        return self.include_interface_name(network['name'])

    def include_interface_name(self, interface_name):
        include_interface = True
        if self.options.include:
            include_interface = False
            for regex in self.options.include:
                if re.match(regex, interface_name):
                    include_interface = True
                    break
        
        exclude_interface = False
        for regex in self.options.exclude:
            if re.match(regex, interface_name):
                exclude_interface = True
                break
        
        return include_interface and not exclude_interface

    def valid_ip_address(self, ip_address):
        if ip_address == '127.0.0.1' or ip_address == '::1' or ip_address.startswith('fe80:'):
            return False

        try:
            # Check if valid IPv4 address
            socket.inet_pton(socket.AF_INET, ip_address)
            return True
        except socket.error:
            if not self.options.include_ipv6:
                return False
            try:
                # Check if valid IPv6 address
                socket.inet_pton(socket.AF_INET6, ip_address)
                return True
            except socket.error:
                return False

    def include_ip_address(self, ip_address):
        # import ipaddress here to contain Python 3.3+ dependency
        if self.options.include_cidr or self.options.exclude_cidr:
            import ipaddress # pylint: disable=import-outside-toplevel
        if not self.valid_ip_address(ip_address):
            return False

        include_ip = True
        if self.options.include_ips or self.options.include_cidr:
            include_ip = False
            for regex in self.options.include_ips:
                if re.match(regex, ip_address):
                    include_ip = True
                    break
            for cidr in self.options.include_cidr:
                if ipaddress.ip_address(ip_address) in ipaddress.ip_network(cidr):  
                    include_ip = True
                    break
        
        exclude_ip = False
        for regex in self.options.exclude_ips:
            if re.match(regex, ip_address):
                exclude_ip = True
                break
        for cidr in self.options.exclude_cidr:
            if ipaddress.ip_address(ip_address) in ipaddress.ip_network(cidr):  
                exclude_ip = True
                break

        return include_ip and not exclude_ip

class SystemInfo(object):
    id = ""
    name = ""
    machine = ""
    kernel = ""
    version_id = ""
    ip_address = ""


def main_list(options, config_path):
    results = {
        'all': {
            'hosts': [],
        },
        '_meta': {
            'hostvars': {},
        }
    }

    proxmox_api = ProxmoxAPI(options, config_path)
    proxmox_api.auth()

    for node in proxmox_api.nodes().get_names():
        try:
            qemu_list = proxmox_api.node_qemu(node)
        except HTTPError as error:
            # the API raises code 595 when target node is unavailable, skip it
            if error.code == 595 or error.code == 596:
                continue
            # if it was some other error, reraise it
            raise error
        results['all']['hosts'] += qemu_list.get_names()
        results['_meta']['hostvars'].update(qemu_list.get_variables())
        if proxmox_api.version().get_version() >= 4.0:
            lxc_list = proxmox_api.node_lxc(node)
            results['all']['hosts'] += lxc_list.get_names()
            results['_meta']['hostvars'].update(lxc_list.get_variables())
        else:
            openvz_list = proxmox_api.node_openvz(node)
            results['all']['hosts'] += openvz_list.get_names()
            results['_meta']['hostvars'].update(openvz_list.get_variables())

        # Merge QEMU and Containers lists from this node
        node_hostvars = qemu_list.get_variables().copy()
        if proxmox_api.version().get_version() >= 4.0:
            node_hostvars.update(lxc_list.get_variables())
        else:
            node_hostvars.update(openvz_list.get_variables())

        # Check only VM/containers from the current node
        for vm in node_hostvars:
            vmid = results['_meta']['hostvars'][vm]['proxmox_vmid']
            try:
                type = results['_meta']['hostvars'][vm]['proxmox_type']
            except KeyError:
                type = 'qemu'
                results['_meta']['hostvars'][vm]['proxmox_type'] = 'qemu'
            try:
                description = proxmox_api.vm_description_by_type(node, vmid, type)['description']
            except KeyError:
                description = None

            try:
                metadata = json.loads(description)
            except TypeError:
                metadata = {}
            except ValueError:
                metadata = {
                    'notes': description
                }
            
            if type == 'qemu':
                # Retrieve information from QEMU agent if installed
                if proxmox_api.qemu_agent(node, vmid):
                    system_info = proxmox_api.qemu_agent_info(node, vmid)
                    results['_meta']['hostvars'][vm]['ansible_host'] = system_info.ip_address
                    results['_meta']['hostvars'][vm]['proxmox_os_id'] = system_info.id
                    results['_meta']['hostvars'][vm]['proxmox_os_name'] = system_info.name
                    results['_meta']['hostvars'][vm]['proxmox_os_machine'] = system_info.machine
                    results['_meta']['hostvars'][vm]['proxmox_os_kernel'] = system_info.kernel
                    results['_meta']['hostvars'][vm]['proxmox_os_version_id'] = system_info.version_id
            else:
                lxc_ip_address = proxmox_api.openvz_ip_address(node, vmid)
                if lxc_ip_address:
                    results['_meta']['hostvars'][vm]['ansible_host'] = lxc_ip_address
                else:
                    # IF IP is empty (due DHCP, take hostname instead)
                    results['_meta']['hostvars'][vm]['ansible_host'] = proxmox_api.lxc_hostname(node, vmid)

            if 'groups' in metadata:
                # print metadata
                for group in metadata['groups']:
                    if group not in results:
                        results[group] = {
                            'hosts': []
                        }
                    results[group]['hosts'] += [vm]

            # Create group 'running'
            # so you can: --limit 'running'
            status = results['_meta']['hostvars'][vm]['proxmox_status']
            if status == 'running':
                if 'running' not in results:
                    results['running'] = {
                        'hosts': []
                    }
                results['running']['hosts'] += [vm]

            if 'proxmox_os_id' in results['_meta']['hostvars'][vm]:
                osid = results['_meta']['hostvars'][vm]['proxmox_os_id']
                if osid:
                    if osid not in results:
                        results[osid] = {
                            'hosts': []
                        }
                    results[osid]['hosts'] += [vm]

            # Create group 'based on proxmox_tags'
            # so you can: --limit 'worker,external-datastore'
            try:
                tags = results['_meta']['hostvars'][vm]['proxmox_tags']
                vm_name = results['_meta']['hostvars'][vm]['proxmox_name']
                tag_list = split_tags(tags)
                for i in range(len(tag_list)):
                    if tag_list[i] not in results:
                        results[tag_list[i]] = {
                            'hosts': []
                        }
                    results[tag_list[i]]['hosts'] += [vm]
            except KeyError:
                pass
           
            results['_meta']['hostvars'][vm].update(metadata)

    # pools
    for pool in proxmox_api.pools().get_names():
        results[pool] = {
            'hosts': proxmox_api.pool(pool).get_members_name(),
        }
    return results

def split_tags(proxmox_tags: str) -> list[str]:
    """
    Splits proxmox_tags delimited by comma and returns a list of the tags.
    """
    tags = proxmox_tags.split(';')
    return tags

def main_host(options, config_path):
    proxmox_api = ProxmoxAPI(options, config_path)
    proxmox_api.auth()

    for node in proxmox_api.nodes().get_names():
        qemu_list = proxmox_api.node_qemu(node)
        qemu = qemu_list.get_by_name(options.host)
        if qemu:
            return qemu.get_variables()

    return {}

def get_env_list_variable(env_var):
    env_value = os.environ.get(env_var, '')
    if env_value:
        return env_value.split(';')
    else:
        return []

def main():
    config_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        os.path.splitext(os.path.basename(__file__))[0] + ".json"
    )

    bool_validate_cert = True
    if os.path.isfile(config_path):
        with open(config_path, "r") as config_file:
            config_data = json.load(config_file)
            try:
                bool_validate_cert = config_data["validateCert"]
            except KeyError:
                pass
    if 'PROXMOX_INVALID_CERT' in os.environ:
        bool_validate_cert = False

    parser = OptionParser(usage='%prog [options] --list | --host HOSTNAME')
    parser.add_option('--list', action="store_true", default=False, dest="list")
    parser.add_option('--host', dest="host")
    parser.add_option('--url', default=os.environ.get('PROXMOX_URL'), dest='url')
    parser.add_option('--username', default=os.environ.get('PROXMOX_USERNAME'), dest='username')
    parser.add_option('--password', default=os.environ.get('PROXMOX_PASSWORD'), dest='password')
    parser.add_option('--token', default=os.environ.get('PROXMOX_TOKEN'), dest='token')
    parser.add_option('--secret', default=os.environ.get('PROXMOX_SECRET'), dest='secret')
    parser.add_option('--pretty', action="store_true", default=False, dest='pretty')
    parser.add_option('--trust-invalid-certs', action="store_false", default=bool_validate_cert, dest='validate')
    parser.add_option('--include', default=get_env_list_variable("INCLUDE_FILTER"), action="append")
    parser.add_option('--exclude', default=get_env_list_variable("EXCLUDE_FILTER"), action="append")
    parser.add_option('--include_ips', default=get_env_list_variable("INCLUDE_IPS_FILTER"), action="append")
    parser.add_option('--exclude_ips', default=get_env_list_variable("EXCLUDE_IPS_FILTER"), action="append")
    parser.add_option('--include_cidr', default=get_env_list_variable("INCLUDE_CIDR_FILTER"), action="append")
    parser.add_option('--exclude_cidr', default=get_env_list_variable("EXCLUDE_CIDR_FILTER"), action="append")
    parser.add_option('--include_ipv6', action="store_true", default=os.environ.get("INCLUDE_IPV6", False), dest='include_ipv6')
    (options, args) = parser.parse_args()

    for option in ['include', 'exclude', 'include_ips', 'exclude_ips', 'include_cidr', 'exclude_cidr']:
        # Split env var list options on ';' to allow multiple values and ensure result is a list
        option_val = getattr(options, option)
        if isinstance(option_val, str):
            setattr(options, option, option_val.split(';'))

    if options.list:
        data = main_list(options, config_path)
    elif options.host:
        data = main_host(options, config_path)
    else:
        parser.print_help()
        sys.exit(1)

    indent = None
    if options.pretty:
        indent = 2
#TODO
    print((json.dumps(data, indent=indent)))


if __name__ == '__main__':
    main()
