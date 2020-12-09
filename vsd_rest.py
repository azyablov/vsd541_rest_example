import os
import sys
import argparse
import requests
import json
import urllib3
import base64
import time
import ipdb
from pprint import pprint
from typing import Union, List
from urllib3.exceptions import InsecureRequestWarning
# requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
urllib3.disable_warnings(category=InsecureRequestWarning)


def nu_get_supported_api_versions(base_url: str) -> Union[bool, List[str]]:
    """ The function requests all possible api versions and selects CURRENT one.
    If something goes wrong empty list is returned.
    :param base_url: URL string
    :return list
    """

    http_session = requests.session()
    http_resp = http_session.get(url=base_url, verify=False)
    ver_supp = False
    if http_resp.ok:
        json_obj = http_resp.json()
    else:
        return ver_supp

    ver_supp = [None]
    # Go throughout list of dicts and extract CURRENT versions
    for item in json_obj['versions']:
        if item['status'] == 'CURRENT':
            # ver_supp.append(item['version'].upper())
            ver_supp[0] = item['version'].upper()
        if item['status'] == 'DEPRECATED':
            ver_supp.append(item['version'].upper())
    # Let's return most recent version as [0]
    ver_supp.sort(reverse=True)
    return ver_supp


def nu_build_api_url(host_base: str, current: bool = True) -> str:
    """
    The function is building API URL for current or deprecated API supported by VSD.
    :param host_base:
    :param current: return current version or deprecated if False
    :return:
    """
    if current:
        return f"{host_base}/nuage/api/{nu_get_supported_api_versions(host_base + '/nuage')[0].replace('.', '_')}"
    else:
        return f"{host_base}/nuage/api/{nu_get_supported_api_versions(host_base + '/nuage')[1].replace('.', '_')}"


def base64_auth(login: str, secret: str) -> str:
    """
    The function returns BASE64 encoded string for AUTH.
    :param login: login
    :param secret: password
    :return:
    """
    auth_str = f"{login}:{secret}"
    auth_b64 = base64.b64encode(auth_str.encode(encoding='utf-8'))
    return auth_b64.decode()


if __name__ == "__main__":
    """
    VSD REST script example entry point.
    """
    argp_desc = sys.argv[0] + ' VSD REST requests lib example'
    parser = argparse.ArgumentParser(prog='stats', description=argp_desc)
    parser.add_argument('--vsd', help='VSD IP/FQDN', action='store',
                        required=True)
    parser.add_argument('-l', help='login with RO rights for csproot', action='store',
                        required=True)
    parser.add_argument('-p', help='password for csproot', action='store',
                        required=True)
    args = parser.parse_args()

    vsd = args.vsd
    login = args.l
    password = args.p
    # Auth string
    auth_string_b64 = base64_auth(login, password)

    org = "csp"
    api_vers = nu_get_supported_api_versions('https://' + vsd + ':8443' + '/nuage')
    api_base = nu_build_api_url('https://' + vsd + ':8443')
    print(f"API base: {api_base}")

    # Check health first )))
    response = requests.get(url=f"https://{vsd}:8443/nuage/health", verify=False)
    r_dict = json.loads(response.text)
    print(20 * '=' + ' VSD health status ' + 20 * '=')
    print(json.dumps(r_dict, indent=4))
    ipdb.set_trace()

    # Get API Tocken
    http_headers ={}
    http_headers["X-Nuage-Organization"] = org
    http_headers["Content-Type"] = "application/json"
    http_headers["Authorization"] = f"XREST {auth_string_b64}"
    print(20 * '=' + ' HTTP headers ' + 20 * '=')
    pprint(http_headers)
    url = f"{api_base}/me"
    response = requests.get(url=f"{api_base}/me", headers=http_headers, verify=False)
    auth_response = response.json()
    ipdb.set_trace()
    print(20 * '=' + ' AUTH response ' + 20 * '=')
    pprint(response.json())
    ipdb.set_trace()
    api_key = auth_response[0]["APIKey"]
    api_key_exp = auth_response[0]["APIKeyExpiry"]//1000
    cur_time = int(time.time())
    # Check expiry time opf API KEY
    if cur_time < api_key_exp:
        http_headers["Authorization"] = f"XREST {base64_auth(login, api_key)}"
        ents = requests.get(url=f"{api_base}/enterprises", headers=http_headers, verify=False).json()
        print(20 * '=' + ' VSD enterprises ' + 20 * '=')
        pprint(ents)

        for e in ents:
            e_id = e['ID']
            for child in ['vms', "domains", "l2domains"]:
                print(20 * '=' + f' VSD enterprise {e["name"]}' + 20 * '=')
                print(20 * '=' + f" Child objects: {child} " + 20 * '=')
                response = requests.get(url=f"{api_base}/enterprises/{e_id}/{child}",
                                        headers=http_headers,
                                        verify=False)
                pprint(f"Response: {response}")
                if response.text:
                    pprint(response.json())
                else:
                    print("NONE")
            ipdb.set_trace()
                # Do your stuff here.....
    else:
        # Reauthenticate since key has been expired
        http_headers["Authorization"] = f"XREST {auth_string_b64}"
        response = requests.get(url=f"{api_base}/me", headers=http_headers, verify=False)
        api_key = auth_response[0]["APIKey"]
        http_headers["Authorization"] = f"XREST {base64_auth(login, api_key)}"
        # Do you stuff here....





