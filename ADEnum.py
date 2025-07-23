import subprocess
import os
from ldap3 import Server, Connection, SASL, GSSAPI, SUBTREE, Tls
import argparse
import ssl
from impacket.ldap import ldaptypes
import fnmatch
import socket

parser = argparse.ArgumentParser(description="Example LDAP tool")
parser.add_argument("--user", help="Username to authenticate", required=True)
parser.add_argument("--password", help="Password for the user", required=True)
parser.add_argument("--server", help="LDAP server address", required=True)
parser.add_argument("--domain", help="Target Domain", required=True)
parser.add_argument("--port", help="LDAP port", default="")
parser.add_argument("--secure", help="LDAP port", default="ldap")
args = parser.parse_args()


# Authentication

def get_kerberos_ticket(username: str, password: str) -> bool:
    """
    Use kinit to obtain a Kerberos ticket using provided username and password.
    Returns True on success, False on failure.
    """
    print(f"Trying Kerberos Authentication to {ldap_server} with kinit as {username}")
    try:
        result = subprocess.run(
            ['kinit', username],
            input=password.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print("kinit failed:", e.stderr.decode().strip())
        return False


# LDAP Configuration
upperDomain = f"{args.domain}".upper()
username = f"{args.user}@{upperDomain}"
password = f"{args.password}"
ldap_server = f"{args.secure}://{args.server}{args.port}"
base_dn = "DC=" + f"{args.domain}".replace(".", ",DC=")


# Request Kerberos ticket
if not get_kerberos_ticket(username, password):
    exit(1)

#server = Server(ldap_server, get_info=ALL)
print("Connecting to LDAP over Kerberos (GSSAPI) ")

tls_config = Tls(validate=ssl.CERT_NONE)
server = Server(ldap_server, use_ssl=True, get_info=None, tls=tls_config)
conn = Connection(server, authentication=SASL, sasl_mechanism=GSSAPI, auto_bind=True, sasl_credentials=(None, None), read_only=True, receive_timeout=10, auto_referrals=True)

# LDAP searches
def domainControllers():
	print("\n")
	search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("==========[Domain Controllers]==========")
	print("Saved to DCs.txt")
	with open("DCs.txt", "w") as f:
		for entry in conn.entries:
		    print(f"{entry.name}")
		    f.write(f"{entry.name}\n")
	return

def domainTrusts():
	print("\n")
	search_filter = '(objectClass=trustedDomain)'
	attributes = ['cn', 'trustPartner', 'trustDirection', 'trustType', 'trustAttributes', 'flatName']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	
	def translate_direction(value):
	    value = str(value).strip()
	    return {
		"0": "Disabled",
		"1": "Inbound",
		"2": "Outbound",
		"3": "Bidirectional"
	    }.get(value, f"Unknown ({value})")
	
	def trustType(value):
	    value = str(value).strip()
	    return {
		"1": "Windows domain not running AD - Downlevel: a trust with a domain that is running a version of Windows NT 4.0 or earlier.",
		"2": "Windows domain running AD - Uplevel: a trust with a domain that is running Windows 2000 or later.",
		"3": "Non-Windows with Kerberos - MIT: a trust with a non-Windows Kerberos realm, typically used for interoperability with UNIX-based systems running MIT Kerberos.",
		"4": "DCE: not used in Windows. Would refer to trusts with a domain running DCE.",
		"5": "ENTRA ID: the trusted domain is in Azure Active Directory."
	    }.get(value, f"Unknown ({value})")	
	
	def trustAttributes(value):
	    value = str(value).strip()
	    return {
		"1": "NON_TRANSITIVE - Trust is not transitive",
		"2": "UPLEVEL_ONLY - Only Windows 2000 and newer operating systems can use the trust",
		"4": "FILTER_SIDS - Domain is quarantined and subject to SID filtering",
		"8": "FOREST_TRANSITIVE - Cross forest trust between forests",
		"16": "CROSS_ORGANIZATION - Domain or forest is not part of the organization",
		"32": "WITHIN_FOREST - Trusted domain is in the same forest",
		"64": "TREAT_AS_EXTERNAL - Trust is treated as an external trust for SID filtering",
		"128": "TRUST_USES_RC4_ENCRYPTION - Set when trustType is TRUST_TYPE_MIT, which can use RC4 keys",
		"512": "TRUST_USES_AES_KEYS - Tickets under this trust are not trusted for delegation",
		"1024": "CROSS_ORGANIZATION_NO_TGT_DELEGATION - Cross-forest trust to a domain is treated as Privileged Identity Management (PIM) trust for the purposes of SID filtering",
		"2048": "PIM_TRUST - Tickets under this trust are trusted for delegation",
	    }.get(value, f"Unknown ({value})")	
	
	
	print("==========[Domain Trusts]==========")
	for entry in conn.entries:
	    print(f"{entry.cn}")
	    print(f"{entry.flatName}")
	    print(f"{entry.trustPartner}")
	    direction_value = entry.trustDirection.value if entry.trustDirection else None
	    direction = translate_direction(int(direction_value)) if direction_value is not None else "N/A"
	    print(f"{direction}")
	    trust_value = entry.trustType.value if entry.trustType else None
	    trusttype = trustType(int(trust_value)) if trust_value is not None else "N/A"
	    print(f"{trusttype}")
	    Attributes_value = entry.trustAttributes.value if entry.trustAttributes else None
	    attributes = trustAttributes(int(Attributes_value)) if Attributes_value is not None else "N/A"
	    print(f"{attributes}")
	    print("\n")
	return
	
def domainUsers():
	print("\n")
	search_filter = '(objectClass=user)'
	attributes = ['sAMAccountName']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Domain Users]==========")
	print("Saved in DomainUsers.txt")
	with open("DomainUsers.txt", "w") as f:
		for entry in conn.entries:
	  	 f.write(f"{entry.sAMAccountName}\n")
	return

def domainGroups():
	print("\n")
	search_filter = '(objectcategory=group)'
	attributes = ['samaccountname']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Domain Groups]==========")
	for entry in conn.entries:
	    print(f"{entry.samaccountname}")
	return

def domainWSUS():
	print("\n")
	search_filter = '(&(objectClass=serviceConnectionPoint)(keywords=Windows Server Update Services))'
	attributes = ['cn', 'serviceBindingInformation', 'distinguishedName']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[WSUS Servers]==========")
	print("WARNING: WSUS not guaranteed to be in LDAP")
	for entry in conn.entries:
	    print(f"WSUS SCP: {entry.cn}")
	    print(f"URL: {entry.serviceBindingInformation}")
	return

def dmsaAccounts():
	print("\n")
	base_dn = "DC=" + f"{args.domain}".replace(".", ",DC=")
	search_filter = '(objectclass=msDS-DelegatedManagedServiceAccount)'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[dMSA acounts]==========")
	print("If you are low priv, you may not be able to see these.")
	print("If you are low priv and CAN see, then you may be able to compromise the account")
	print("More info: https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/ \n")
	for entry in conn.entries:
	    print(f"Name: {entry.name}") 
	print("\nNext steps: ")
	print(f"\nimpacket-lookupsid '{args.domain}/{args.user}':'{args.password}'@{args.server} | grep '\$'\n")
	print("Then eleminate from this list what hosts you cannot find via LDAP searches\n")
	print("\n------------------------------------------------\n")
	print("\n= Alt serach - may or may not work for low priv=\n")
	base_dn = "CN=Managed Service Accounts,DC=" + f"{args.domain}".replace(".", ",DC=")
	search_filter = '(distinguishedname=*)'
	attributes = ['name', 'objectclass']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	for entry in conn.entries:
	    if "msDS-DelegatedManagedServiceAccount" in entry.objectClass.values:
               print(f"Name: {entry.name} - {entry.objectClass}")
	
	base_dn = "DC=" + f"{args.domain}".replace(".", ",DC=")
	return


def gmsa():
	print("\n")
	search_filter = '(objectClass=msDS-GroupManagedServiceAccount)'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[GMSA Account]========== - To expand later")
	for entry in conn.entries:
	    print(f"{entry}")
	print("\n")
	search_filter = '(PrincipalsAllowedToRetrieveManagedPassword=*)'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	for entry in conn.entries:
	    print(f"{entry}")	    
	return

def msa():
	print("\n")
	search_filter = '(objectClass=msDS-ManagedServiceAccount)'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Managed Service Account]========== - To expand later")
	for entry in conn.entries:
	    print(f"{entry}")
	print("\n")
	search_filter = '(PrincipalsAllowedToRetrieveManagedPassword=*)'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	for entry in conn.entries:
	    print(f"{entry}")	    
	return


def memberProtectedUsers():
	print("\n")
	search_filter = '(&(objectCategory=group)(name=protected users))'
	attributes = ['member']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Members of the protected users group]==========")
	print("Accounts cannot be delegated")
	print("Forces Kerberos authentication (NTLM auth disabled)")
	print("Reduces credential lifetime (e.g. TGT lifetime is shortened to 4 hours)")
	print("Prevents caching of plaintext credentials or weaker hashes")
	print(f"\n")
	for entry in conn.entries:
	    print(f"{entry.member}\n")
	return

def noDelegation():
	print("\n")
	search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=1048576)'
	attributes = ['samaccountname']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Accounts marked for No Delegation]==========")
	print("Accounts cannot be delegated - No S4U for example")
	print(f"\n")
	for entry in conn.entries:
	    print(f"{entry.samaccountname}")
	return
	    
def smartCards():
	print("\n")
	search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=262144)'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Accounts that require smart cards for interaction]==========")
	print("Users must use a smart card to sign into the network")
	print(f"\n")
	for entry in conn.entries:
	    print(f"{entry.name}")
	return

def noPassword():
	print("\n")
	search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=32)'
	attributes = ['sAMAccountName']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Accounts where a password is not required]==========")
	print("Attempt to authenticate to host with no password")
	print(f"\n")
	print("Saved in NoPwdReq.txt")
	with open("NoPwdReq.txt", "w") as f:
		for entry in conn.entries:
	  	 f.write(f"{entry.sAMAccountName}\n")
	return

def interdomainTrust():
	print("\n")
	search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=2048)'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Interdomain Trust]==========")
	print("Accounts trusted for a system domain that trusts other domains")
	print(f"\n")
	for entry in conn.entries:
	    print(f"{entry.name}")
	return

def ldapDescriptions():
	print("\n")
	search_filter = '(&(objectCategory=*)(description=*))'
	attributes = ['sAMAccountName']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Enumerating LDAP descriptions]==========")
	print(f"\n")
	print("Saved in ldapDescriptions.txt")
	with open("ldapDescriptions.txt", "w") as f:
		for entry in conn.entries:
	  	 f.write(f"{entry.sAMAccountName}\n")
	return

def maq():
	print("\n")
	search_filter = '(ms-DS-MachineAccountQuota=*)'
	attributes = ['ms-ds-machineaccountquota']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Enumerating current user's MAQ]==========")
	print("Number of computer accounts that your account can create")
	print(f"\n")
	for entry in conn.entries:
	    print(f"MAQ: {entry['ms-DS-MachineAccountQuota']}")
	return
	
def domainGPOs():
	print("\n")
	search_filter = '(objectCategory=groupPolicyContainer)'
	attributes = ['displayname', 'gpcfilesyspath']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Enumerating Domain GPOs==========")
	print(f"\n")
	for entry in conn.entries:
	    print(f"{entry.displayname}: {entry.gpcfilesyspath}")
	return
	
def denyPolicies():
	print("\n")
	print("=======[Checking for possible deny policies: $DC]==========")
	print("To do")
	return

def currentGPOs():
	print("\n")
	print("=======[Checking for currentGPOs to user]==========")
	print("To do")
	return	

def dangerousAttributes():
	print("=======[Enumerate dangerous user attributes (not exhaustive)==========")
	print("Need to look into the format of each, belive its in UTF-8 format")
	print("\n")
	search_filter = '(UserPassword=*)'
	attributes = ['name', 'userpassword']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("Users with the 'userPassword' attribute")
	for entry in conn.entries:
	    print(f"{entry.name}, {entry.userpassword}")

	print("\n")
	search_filter = '(unicodePwd=*)'
	attributes = ['name', 'unicodepwd']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("Users with the 'unicodePwd' attribute")
	for entry in conn.entries:
	    print(f"{entry.name}, {entry.unicodepwd}")

	print("\n")
	search_filter = '(unixUserPassword=*)'
	attributes = ['name', 'unixuserpassword']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("Users with the 'unixUserPassword' attribute")
	for entry in conn.entries:
	    print(f"{entry.name}, {entry.unixuserpassword}")
	    
	print("\n")
	search_filter = '(msSFU30Password=*)'
	attributes = ['name', 'mssfu30password']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("Users with the 'msSFU30Password' attribute")
	for entry in conn.entries:
	    print(f"{entry.name}, {entry.mssfu30password}")

	print("\n")
	search_filter = '(orclCommonAttribute=*)'
	attributes = ['name', 'orclcommonattribute']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("Users with the 'orclCommonAttribute' attribute")
	for entry in conn.entries:
	    print(f"{entry.name}, {entry.orclcommonattribute}")

	print("\n")
	search_filter = '(defender-tokenData=*)'
	attributes = ['name', 'defender-tokendata']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("Users with the 'defender-tokenData' attribute")
	for entry in conn.entries:
	    print(f"{entry.name}, {entry.defender-tokendata}")

	print("\n")
	search_filter = '(dBCSPwd=*)'
	attributes = ['name', 'dbcspwd']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("Users with the 'dBCSPwd' attribute")
	for entry in conn.entries:
	    print(f"{entry.name}, {entry.dbcspwd}")

	return

def kerberoast():
	print("\n")
	search_filter = '(&(objectCategory=user)(servicePrincipalname=*))'
	attributes = ['name', 'serviceprincipalname']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Kerberoast Users]==========")
	for entry in conn.entries:
	    print(f"{entry.name}, {entry.serviceprincipalname}")
	return

def asreproast():
	print("\n")
	search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[ASREP roastable Users]==========")
	for entry in conn.entries:
	    print(f"{entry.name}")
	return

def adcs():
	print("\n")
	search_filter = '(objectClass=pKIEnrollmentService)'
	attributes = ['dnshostname', 'displayname', 'mspki-enrollment-servers', 'certificatetemplates']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[ADCS]==========")
	print("Enumerate ADCS servers. Enumerate with further tools")
	for entry in conn.entries:
	    print(f"Hostname: {entry.dnshostname}")
	    print(f"CA name: {entry.displayname}")
	    print(f"Enrollment endpoints: {entry['mspki-enrollment-servers']}")
	    print(f"{entry.certificatetemplates}")
	return
	
def ldapSec():
	print("\n")
	print("=======[LDAP Signing and channel binding]==========\n")
	
	stream = os.popen(f"nxc ldap DCs.txt")
	output = stream.read()
	print(output)
	return

def unconstrainedDelegation():
	print("\n")
	search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Unconstrained Delegation hosts]==========\n")
	print("Machines / users that can impersonate any domain user domain wide")
	for entry in conn.entries:
	    print(f"{entry.name}")
	return

def constrainedDelegation():
	print("\n")
	search_filter = '(msds-allowedtodelegateto=*)'
	attributes = ['name', 'msds-allowedtodelegateto']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Constrained Delegation hosts]==========\n")
	print("Machines / users that can impersonate any domain user on specified host/service")
	for entry in conn.entries:
	    print(f"{entry.name}, {entry['msds-allowedtodelegateto']}")
	return

def hostsRBDC():
	print("\n")
	print("=======[Hosts with the RBCD attribute]==========\n")
	search_filter = '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)'
	attributes = ['name', 'msDS-AllowedToActOnBehalfOfOtherIdentity']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("Machines / users that can impersonate any domain user on specified host/service")
	for entry in conn.entries:
	    print(f"\nHosts that have RBCD rights to: {entry.name}")
	    raw_sd = entry['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values[0]
	    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
	    if len(sd["Dacl"].aces) > 0:
	      for ace in sd["Dacl"].aces:
	        objsid = "objectSid=" + ace["Ace"]["Sid"].formatCanonical() + ""
	        search_filter = f'({objsid})'
	        attributes = ['sAMAccountName']
	        conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	        for entry in conn.entries:
	        	print(f"{entry.sAMAccountName}\n")
	return


def laps():
	print("\n")
	search_filter = '(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[LAPS]==========")
	for entry in conn.entries:
	    print(f"{entry}")
	return

def sccm():
	print("\n")
	search_filter = '(objectClass=mSSMSManagementPoint)'
	attributes = ['dnshostname', 'mssmssitecode', 'name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[SCCM]==========")
	print("SharpSCCM.exe local site-info --no-banner")
	for entry in conn.entries:
	    print(f"Host Name: {entry.dnshostname}")
	    print(f"Site Code: {entry.mssmssitecode}")
	    print(f"name: {entry.name}")
	return

def mssql():
	print("\n")
	search_filter = '(&(objectCategory=computer)(Name=*SQL*))'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[MSSQL]==========")
	print("Not perfect, computer accounts based off name")
	print("Sill enum via nmap with -sV")
	for entry in conn.entries:
	    print(f"{entry.name}")
	return

def dnsPermissions():
	print("\n")
	print("To do")
	return

def obsoleteHosts():
	print("\n")
	search_filter = '(objectCategory=computer)'
	attributes = ['cn', 'operatingSystem']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Obsolete host enumeration]==========")
	print("Just pulled from LDAP")
	legacy_os_patterns = [
	  "Windows XP*", "Windows 7*", "Windows 8*", "Windows Server 2003*",
	  "Windows Server 2008*", "Windows Server 2012*", "Windows Vista*", "Windows 2000"]
	for entry in conn.entries:
	    os_name = str(entry.operatingSystem)
	    try:
	      ip = socket.gethostbyname(f"{entry.cn}")
	    except:
	      ip = "Could not resolve"
	      continue
	    
	    if any(fnmatch.fnmatch(os_name, pattern) for pattern in legacy_os_patterns):
               print(f"{entry.cn} - {os_name} - {ip}")
	return

def passPolicy():
	print("\n")
	print("=======[Checking password policy, GPOs, and fine grain policies]==========")
	base_dn = "DC=" + f"{args.domain}".replace(".", ",DC=")
	search_filter = '(objectClass=domain)'
	attributes = ['minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'minPwdAge', 'lockoutThreshold', 'lockoutDuration', 'lockoutObservationWindow', 'pwdProperties']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("= Domain default =")
	for entry in conn.entries:
	    print(f"Min password length: {entry.minPwdLength}")
	    print(f"Pass history length: {entry.pwdHistoryLength}")
	    print(f"Max password age: {entry.maxPwdAge}")
	    print(f"Min password age: {entry.minPwdAge}")
	    print(f"Lockout Threshold: {entry.lockoutThreshold}")
	    print(f"Lockout Duration: {entry.lockoutDuration}")
	    print(f"Lockout Observation Window: {entry.lockoutObservationWindow}")
	    print(f"Password Properties: {entry.pwdProperties}\n")
	print("= Checking other GPOs - To add =\n")
	print("= fine grain policies =")
	base_dn = "CN=Password Settings Container,CN=System,DC=" + f"{args.domain}".replace(".", ",DC=")    
	search_filter = '(objectClass=msDS-PasswordSettings)'
	attributes = ['name', 'msDS-PasswordSettingsPrecedence', 'msDS-PasswordReversibleEncryptionEnabled', 'msDS-PasswordHistoryLength', 'msDS-PasswordComplexityEnabled', 'msDS-MinimumPasswordLength', 'msDS-MinimumPasswordAge', 'msDS-MaximumPasswordAge', 'msDS-LockoutThreshold', 'msDS-LockoutObservationWindow', 'msDS-LockoutDuration', 'msDS-PSOAppliesTo']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	for entry in conn.entries:
	    print(f"PasswordSettingsPrecedence {entry['msDS-PasswordSettingsPrecedence']}")
	    print(f"PasswordReversibleEncryptionEnabled {entry['msDS-PasswordReversibleEncryptionEnabled']}")
	    print(f"PasswordHistoryLength {entry['msDS-PasswordHistoryLength']}")
	    print(f"PasswordComplexityEnabled {entry['msDS-PasswordComplexityEnabled']}")
	    print(f"MinimumPasswordLength {entry['msDS-MinimumPasswordLength']}")
	    print(f"MinimumPasswordAge {entry['msDS-MinimumPasswordAge']}")
	    print(f"MaximumPasswordAge {entry['msDS-MaximumPasswordAge']}")
	    print(f"LockoutThreshold {entry['msDS-LockoutThreshold']}")
	    print(f"LockoutObservationWindow {entry['msDS-LockoutObservationWindow']}")
	    print(f"LockoutDuration {entry['msDS-LockoutDuration']}")
	    print(f"PSOAppliesTo {entry['msDS-PSOAppliesTo']}")
	base_dn = "DC=" + f"{args.domain}".replace(".", ",DC=")
	return

# Call LDAP searches
domainControllers()
domainTrusts()
domainUsers()
domainGroups()
domainWSUS()
memberProtectedUsers()
dmsaAccounts()
gmsa()
msa()
noDelegation()
smartCards()
noPassword()
interdomainTrust()
ldapDescriptions()
maq()
domainGPOs()
denyPolicies()
currentGPOs()
dangerousAttributes()
kerberoast()
asreproast()
base_dn = "CN=Configuration,DC=" + f"{args.domain}".replace(".", ",DC=")
adcs()
base_dn = "DC=" + f"{args.domain}".replace(".", ",DC=")
ldapSec()
unconstrainedDelegation()
constrainedDelegation()
hostsRBDC()
laps()
sccm()
mssql()
dnsPermissions()
obsoleteHosts()
passPolicy()

conn.unbind()
