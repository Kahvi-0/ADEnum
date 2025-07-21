import subprocess
import os
from ldap3 import Server, Connection, SASL, GSSAPI, SUBTREE, ALL
import argparse

parser = argparse.ArgumentParser(description="Example LDAP tool")
parser.add_argument("--user", help="Username to authenticate", required=True)
parser.add_argument("--password", help="Password for the user", required=True)
parser.add_argument("--server", help="LDAP server address", required=True)
parser.add_argument("--domain", help="Target Domain", required=True)
parser.add_argument("--port", help="LDAP port", default="")
parser.add_argument("--secure", help="LDAP port", default="ldap")
args = parser.parse_args()

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


# Configuration
username = f"{args.user}"  # Use full UPN
password = f"{args.password}"
ldap_server = f"{args.secure}://{args.server}{args.port}"
base_dn = "DC=" + f"{args.domain}".replace(".", ",DC=")

# Request Kerberos ticket
if not get_kerberos_ticket(username, password):
    exit(1)

#server = Server(ldap_server, get_info=ALL)
print("Connecting to LDAP over Kerberos (GSSAPI) ")

server = Server(ldap_server, use_ssl=True, get_info=None)

conn = Connection(server, authentication=SASL, sasl_mechanism=GSSAPI, auto_bind=True)

# LDAP searches


# Output results

def domainControllers():
	print("\n")
	search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("==========[Domain Controllers]==========")
	for entry in conn.entries:
	    print(f"{entry.name}")
	return

def domainTrusts():
	print("\n")
	print("Domain Trusts")
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
	for entry in conn.entries:
	    print(f"{entry.member}\n")
	return

def noDelegation():
	print("\n")
	search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=1048576)'
	attributes = ['samaccountname']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("Accounts marked for No Delegation")
	print("Accounts cannot be delegated - No S4U for example")
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
	for entry in conn.entries:
	    print(f"{entry.name}")
	return

def ldapDescriptions():
	print("\n")
	search_filter = '(&(objectCategory=*)(description=*))'
	attributes = ['sAMAccountName']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Enumerating LDAP descriptions]==========")
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
	for entry in conn.entries:
	    print(f"MAQ: {entry['ms-DS-MachineAccountQuota']}")
	return
	
def denyPolicies():
	print("\n")
	print("Checking for possible deny policies")
	print("To do")
	return

def currentGPOs():
	print("\n")
	print("Checking for currentGPOs to user")
	print("To do")
	return	

print("=======[Enumerate dangerous user attributes (not exhaustive)==========")
print("Need to look into the format of each, belive its in UTF-8 format")

def dangerousAttributes():
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
	print("LDAP Signing and channel binding")
	print("To do")
	return

def unconstrainedDelegation():
	print("\n")
	search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Unconstrained Delegation hosts]==========")
	print("Machines / users that can impersonate any domain user domain wide")
	for entry in conn.entries:
	    print(f"{entry.name}")
	return

def constrainedDelegation():
	print("\n")
	search_filter = '(msds-allowedtodelegateto=*)'
	attributes = ['name', 'msds-allowedtodelegateto']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[Constrained Delegation hosts]==========")
	print("Machines / users that can impersonate any domain user on specified host/service")
	for entry in conn.entries:
	    print(f"{entry.name}, {entry['msds-allowedtodelegateto']}")
	return

def hostsRBDC():
	print("\n")
	print("Hosts with the RBCD attribute")
	print("To do")
	return

def gmsa():
	print("\n")
	search_filter = '(mobjectClass=msDS-ManagedServiceAccount)'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	print("=======[GMSA Service]========== - To expand later")
	for entry in conn.entries:
	    print(f"{entry}")
	print("\n")
	search_filter = '(PrincipalsAllowedToRetrieveManagedPassword=*)'
	attributes = ['name']
	conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
	for entry in conn.entries:
	    print(f"{entry}")	    
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
	print("To do")
	return

def passPolicy():
	print("\n")
	print("Checking password policy")
	print("To do")
	return

# Call LDAP searches
domainControllers()
domainTrusts()
domainUsers()
domainGroups()
memberProtectedUsers()
noDelegation()
smartCards()
noPassword()
interdomainTrust()
ldapDescriptions()
maq()
denyPolicies()
currentGPOs()
dangerousAttributes()
kerberoast()
asreproast()
adcs()
ldapSec()
unconstrainedDelegation()
constrainedDelegation()
hostsRBDC()
gmsa()
laps()
sccm()
mssql()
dnsPermissions()
obsoleteHosts()
passPolicy()

conn.unbind()
