#!/bin/env python
import sys
import inspect
import subprocess
from pathlib import Path
import yaml
import json
import re
import os
import ipaddress
import socket

# デバッグモード
DEBUGMODE = False

# 生成物の出力先
KEYDIR = './keys'
CONFDIR = './configs'


def debug(mes):
    if DEBUGMODE:
        f = inspect.currentframe().f_back.f_code.co_name
        print(f"[DEBUG] {f}(): {mes}", file=sys.stderr)

def load_yaml(fname):
    with open(fname, 'r') as yaml_file:
        data = yaml.safe_load(yaml_file)
    return data

def load_json(fname):
    with open(fname, 'r') as json_file:
        data = json.load(fname)
    return data

def is_ipv4(ip):
    if ip == None:
        return False
    try:
        ipaddress.IPv4Network(ip, strict=False)
        return True
    except ipaddress.AddressValueError:
        return False

def is_ipv6(ip):
    if ip == None:
        return False
    try:
        ipaddress.IPv6Network(ip, strict=False)
        return True
    except ipaddress.AddressValueError:
        return False

def is_ip(ip):
    return is_ipv4(ip) or is_ipv6(ip)

def is_domain(dom):
    if re.match(r'^(?!.*\-$)(?!^\-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*(?<!-)$', dom):
        return True
    return False

def get_ip_prefixlen(cidr):
    if cidr == None:
        return None
    if not re.match(r'^.*/[0-9]{1,3}$', cidr):
        raise ValueError(f"{cidr}: is not CIDR")
    if is_ipv4(cidr):
        network = ipaddress.IPv4Network(cidr, strict=False)
    elif is_ipv6(cidr):
        network = ipaddress.IPv6Network(cidr, strict=False)
    else:
        raise ValueError(f"{cidr}: is not CIDR")
    return network.prefixlen

def get_pure_ip(ip):
    if ip == None:
        return None
    ip = re.sub(r'/[0-9]{1,3}$', '', ip)
    return ip

def is_ip_in_network(ip, cidr):
    if ip == None or cidr == None:
        return False
    if not re.match(r'^.*/[0-9]{1,3}$', cidr):
        raise ValueError(f"{cidr}: is not CIDR")
    if not is_ip(ip) or not is_ip(cidr):
        raise ValueError(f"input is something that is not IP")
    network = ipaddress.ip_network(cidr, strict=False)
    ip_address = ipaddress.ip_address(ip)
    return ip_address in network

def combine_ip_with_network(ip, network_cidr):
    if ip == None or network_cidr == None:
        return None
    network = ipaddress.ip_network(network_cidr, strict=False)
    
    ip_address = ipaddress.ip_address(ip)
    
    if ip_address not in network:
        raise ValueError(f"{ip}: is not in the network {network_cidr}")
    
    return f"{ip}/{network.prefixlen}"

def increment_ip(ip, increment=1):
    if ip == None:
        return None
    ip_obj = ipaddress.ip_address(ip)
    # IPアドレスを整数に変換してインクリメント
    incremented_ip = ip_obj + increment
    # インクリメント後のIPアドレスを戻す
    return str(incremented_ip)


def mkkey(private=None):
    if private == None:
        result = subprocess.run(
            ['wg', 'genkey'],
            text=True,
            capture_output=True
        )
        private = result.stdout
    result = subprocess.run(
        ['wg', 'pubkey'],
        text=True,
        input=private,
        capture_output=True
    )
    public = result.stdout
    return private.replace('\n', ''), public.replace('\n', '')

def mkpsk():
    result = subprocess.run(
        ['wg', 'genpsk'],
        text=True,
        capture_output=True
    )
    psk = result.stdout
    return psk.replace('\n', '')

def savekeypair(name: str):
    global KEYDIR
    path_to_keys = Path(KEYDIR)
    if not path_to_keys.exists():
        path_to_keys.mkdir(exist_ok=True)
    elif not path_to_keys.is_dir():
        raise FileExistsError(f"{path_to_keys}: already exists")
    path_to_prikey = Path(f"{path_to_keys}/{name}.key")
    path_to_pubkey = Path(f"{path_to_keys}/{name}.pub")
    if path_to_pubkey.exists() and (not path_to_prikey.exists()):
        with open(f"{path_to_pubkey}", "r") as f:
            key_pair = ('(Unknown)', f.readline().replace('\n', ''))
            return key_pair
    if path_to_prikey.exists():
        os.chmod(f"{path_to_prikey}", 0o600)
        with open(f"{path_to_prikey}", "r") as f:
            key_pair = mkkey(f.readline().replace('\n', ''))
            return key_pair
    key_pair = mkkey()
    with open(f"{path_to_prikey}", "w") as f:
        print(f"{key_pair[0]}", file=f)
    os.chmod(f"{path_to_prikey}", 0o600)
    with open(f"{path_to_pubkey}", "w") as f:
        print(f"{key_pair[1]}", file=f)
    return key_pair

def savepsk(name1: str, name2: str):
    global KEYDIR
    path_to_keys = Path(KEYDIR)
    if not path_to_keys.exists():
        path_to_keys.mkdir(exist_ok=True)
    elif not path_to_keys.is_dir():
        raise FileExistsError(f"{path_to_keys}: already exists")
    
    path_to_psk1 = Path(f"{path_to_keys}/PSK_{name1}_{name2}.key")
    path_to_psk2 = Path(f"{path_to_keys}/PSK_{name2}_{name1}.key")
    if path_to_psk1.exists():
        os.chmod(f"{path_to_psk1}", 0o600)
        with open(f"{path_to_psk1}", "r") as f:
            psk = f.readline()
        return psk.replace('\n', '')
    elif path_to_psk2.exists():
        os.chmod(f"{path_to_psk2}", 0o600)
        with open(f"{path_to_psk2}", "r") as f:
            psk = f.readline()
        return psk.replace('\n', '')
    else:
        with open(f"{path_to_psk1}", "w") as f:
            os.chmod(f"{path_to_psk1}", 0o600)
            psk = mkpsk()
            print(f"{psk}", file=f)
        return psk

def mkconf(common: dict, this: dict, others: list):
    global CONFDIR
    path_to_keys = Path(CONFDIR)
    if not path_to_keys.exists():
        path_to_keys.mkdir(exist_ok=True)
    elif not path_to_keys.is_dir():
        raise FileExistsError(f"{path_to_keys}: already exists")
    

    subnet = common['subnet']
    address = []
    for a in this["address"]:
        yes = False
        for s in subnet:
            if is_ip_in_network(a, s):
                yes = True
                address.append(combine_ip_with_network(a, s))
            elif a == None:
                yes = True
        if not yes:
            raise ValueError(f"{a}: is not in subnets")
    
    name = this['name']
    role = this['role']
    port = this.get('port', None)
    mtu = common.get('mtu', None)
    dns = common.get('dns', None)

    with open(f"{path_to_keys}/{name}.conf", "w") as f:
        print("[Interface]", file=f)
        print(f"Address = {', '.join(address)}", file=f)
        print(f"PrivateKey = {savekeypair(name)[0]}", file=f)
        if port != None: print(f"ListenPort = {int(port)}", file=f)
        if mtu != None: print(f"MTU = {int(mtu)}", file=f)
        if dns != None and address != dns: print(f"DNS = {dns}", file=f)
        
        for p in others:
            keep = common.get('keep', None)
            keep = p.get('keep', keep)
            if p == this:
                continue
            if role == 'client' and p['role'] == 'client':
                continue
            print(f"# {str(p['name'])}", file=f)
            print("[Peer]", file=f)
            print(f"PublicKey = {savekeypair(p['name'])[1]}", file=f)
            if common['psk'] != None:
                if common['psk']:
                    print(f"PresharedKey = {savepsk(name, p['name'])}", file=f)
            if p['role'] == 'server': print(f"Endpoint = {str(p['endpoint'])}:{int(p['port'])}", file=f)
            if keep != None and role == 'client': print(f"PersistentKeepalive = {int(keep)}", file=f)
            if p['role'] == 'server':
                print(f"AllowedIPs = {', '.join(common['subnet'])}", file=f)
            else:
                addresses = []
                for a in p['address']:
                    if is_ipv4(a):
                        addresses.append(a + '/32')
                    elif is_ipv6(a):
                        addresses.append(a + '/128')
                print(f"AllowedIPs = {', '.join(addresses)}", file=f)
    os.chmod(f"{path_to_keys}/{name}.conf", 0o600)

def auto_ip(common: dict, peers: list):
    used_ipv4 = []
    used_ipv6 = []
    last_ipv4 = get_pure_ip(common['subnet'][0])
    last_ipv6 = get_pure_ip(common['subnet'][1])
    for i in peers:
        if 'address' in i:
            for j in i['address']:
                if is_ipv4(j):
                    used_ipv4.append(j)
                elif is_ipv6(j):
                    used_ipv6.append(j)
                elif j == None:
                    pass
                else:
                    raise ValueError(f"{j}: is not IP address")
    
    for i in peers:
        if not 'address' in i:
            ipv4 = increment_ip(last_ipv4)
            ipv6 = increment_ip(last_ipv6)
            if ipv4 != None:
                while ipv4 in used_ipv4:
                    debug(f"{ipv4}: already used. Regenerate.")
                    ipv4 = increment_ip(ipv4)
            if ipv6 != None:
                while ipv6 in used_ipv6:
                    debug(f"{ipv6}: already used. Regenerate.")
                    ipv6 = increment_ip(ipv6)
            if ipv4 != None:
                if not is_ip_in_network(ipv4, common['subnet'][0]):
                    raise ValueError(f"too many addresses")
            if ipv6 != None:
                if not is_ip_in_network(ipv6, common['subnet'][1]):
                    raise ValueError(f"too many addresses")
            if ipv4 != None:
                used_ipv4.append(ipv4)
            if ipv6 != None:
                used_ipv6.append(ipv6)
            i['address'] = [ipv4, ipv6]
    return peers

def test3():
    domains = [
        "google.com",
        "ok-homeserver.f5.si",
        "jijj",
        "github.ios",
    ]
    for i in domains:
        if is_domain(i):
            print(f"{i}は有効")
def test4():
    peer = [
        {
            'role': 'server',
            'name': 'Server1',
            'address': ['10.0.0.1', 'fd00::1'],
            'port': 51820,
            'endpoint': 'example1.com'
        },
        {
            'role': 'client',
            'name': 'Client1',
            'address': ['10.0.0.2', 'fd00::2']
        },
        {
            'role': 'client',
            'name': 'Client2',
            'address': ['10.0.0.3', 'fd00::3']
        },
        {
            'role': 'server',
            'name': 'Server2',
            'address': ['10.0.0.4', 'fd00::4'],
            'port': 51821,
            'endpoint': 'example2.com'
        },
        {
            'role': 'client',
            'name': 'Client3',
            'address': ['10.0.0.5', 'fd00::5']
        }
    ]
    common = {
        'subnet': ['10.0.0.0/24', 'fd00::/64'],
        'psk': True,
        'keep': 25
    }
    for i in peer:
        mkconf(common, i, peer)
def test5():
    key = mkkey()
    psk = mkpsk()
    print(f"PrivateKey = {key[0]}")
    print(f"PublicKey = {key[1]}")
    print(f"PresharedKey = {psk}")
def test6():
    peer = [
        {
            'role': 'server',
            'name': 'Server1',
            'port': 51820,
            'endpoint': 'example1.com'
        },
        {
            'role': 'client',
            'name': 'Client1',
            'address': [None, 'fd00::1']
        },
        {
            'role': 'client',
            'name': 'Client2'
        },
        {
            'role': 'server',
            'name': 'Server2',
            'port': 51821,
            'endpoint': 'example2.com'
        },
        {
            'role': 'client',
            'name': 'Client3'
        }
    ]
    common = {
        'subnet': ['192.168.144.0/24', 'fd00::/64'],
        'psk': True,
        'keep': 25
    }
    peer = auto_ip(common, peer)
    for i in peer:
        mkconf(common, i, peer)

def usage(name):
    print(f"Usage: {name} [options...] <JSON or YAML file path>")
    print(f"short\tlong\t\tmeaning")
    print(f"-h\t--help\t\tShow usage")
    print(f"\t\t--usage")
    print(f"\t\t--debug\t\tRun with debug mode")
    print(f"-v\t--version\t\tShow version")

def version():
    print(f"v0.0.1")

def main(argv):
    global DEBUGMODE
    if len(argv) < 2:
        print(f"Try '{argv[0]} --help' for more information.", file=sys.stderr)
        exit(1)
    shortopt = re.compile(r'^-[A-Za-z0-9]$')
    longopt = re.compile(r'^--[A-Za-z0-9]+$')
    confpath = None
    for i in argv:
        if shortopt.match(i):
            if i == '-h':
                usage(argv[0])
                exit(0)
            elif i == '-v':
                version()
                exit(0)
            else:
                print(f"unrecognized option '{i}'", file=sys.stderr)
                exit(1)
        elif longopt.match(i):
            if i == '--help' or i == '--usage':
                usage(argv[0])
                exit(0)
            elif i == '--version':
                version()
                exit(0)
            elif i == '--debug':
                DEBUGMODE = True
            else:
                print(f"unrecognized option '{i}'", file=sys.stderr)
                exit(1)
        else:
            confpath = Path(i)

    if confpath == None:
        confpath = Path(input('Config file path > '))
    
    if not confpath.exists():
        print(f"{confpath}: no such file or directory", file=sys.stderr)
        exit(1)
    
    if confpath.is_dir():
        print(f"{confpath}: Is a directory", file=sys.stderr)
        exit(1)
    
    parent = confpath.parent

    os.chdir(parent)
    
    if re.match(r'.*\.json$', str(confpath)):
        data = load_json(confpath)
    elif re.match(r'.*\.yaml$', str(confpath)):
        data = load_yaml(confpath)
    else:
        print(f"{confpath}: Is not supported format", file=sys.stderr)
        exit(1)
    
    common = data['common']
    peer = data['peers']
    peer = auto_ip(common, peer)
    for i in peer:
        mkconf(common, i, peer)

if __name__ == '__main__':
    main(sys.argv)
