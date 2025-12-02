#!/bin/bash

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
NC="\e[0m"

usage() {
    echo ""
    echo -e "${RED}USAGE:${NC}"
    echo "ADEnum.sh [-u domain\user] [-p password] [-d domain] [-t dc] [-v LDAP/LDAPS] [-l LDAP port]   "
    echo 'example: ./ADEnum.sh -u "LAB\Administrator" -p Password123 -d lab.local -t dc2'
    exit 1
}

USER=""
PASS=''
DC=""
Domain=""
LDAPv=ldap
LDAPport=389

while getopts ":u:p:v:d:t:l:" opt; do
  case $opt in
    u) USER="$OPTARG" ;;
    p) PASS="$OPTARG" ;;
    v) LDAPv="$OPTARG" ;;
    d) Domain="$OPTARG" ;;
    t) DC="$OPTARG" ;;
    l) LDAPport="$OPTARG" ;;
    \?) echo "Invalid option: -$OPTARG"; usage ;;
    :) echo "Option -$OPTARG requires an argument."; usage ;;
  esac
done

DomainParsed=$(echo "$Domain" | awk -F. '{for(i=1;i<=NF;i++) printf "DC=%s%s", $i, (i<NF?",":"")}')
shift $((OPTIND - 1))


Command=(ldapsearch -LLL -x -H $LDAPv://$DC:$LDAPport -D $USER -w $PASS -b "$DomainParsed")

${Command[@]} > /dev/null

# Checks if the first command succeeds or else it exits
if [[ $? -ne 0 ]]; then
    echo "LDAPSEARCH FAILED — exiting."
    usage
    exit 1
fi

echo "=====[Domain Controllers]====="
${Command[@]} "(userAccountControl:1.2.840.113556.1.4.803:=8192)" name | grep name | awk -F " " '{print substr($0, index($0,$2))}' | tee dcs.txt

echo "=====[Domain Trusts - To fix]====="
${Command[@]} "(objectClass=trustedDomain)" cn trustPartner trustDirection trustType trustAttributes flatName

echo "=====[Domain Trusts - Interdomain Trust]====="
echo "INTERDOMAIN_TRUST_ACCOUNT - is a permit to TrustedDomain an account for a system domain that trusts other AD DOMAINs"
${Command[@]} "(userAccountControl:1.2.840.113556.1.4.803:=2048)" name | grep name

echo "=====[Domain Users - Saved to DomainUsers-AuthenticatedLDAP.txt]====="
${Command[@]} "(objectClass=user)" sAMAccountName | grep sAMAccountName.* | awk -F " " '{print substr($0, index($0,$2))}' > DomainUsers-AuthenticatedLDAP.txt

echo "=====[Domain Users that do not require password- Saved to DomainUsers-NoPwdRequired.txt]====="
${Command[@]} "(userAccountControl:1.2.840.113556.1.4.803:=32)" sAMAccountName | grep sAMAccountName | awk -F " " '{print substr($0, index($0,$2))}'

echo "=====[Domain Groups]====="
${Command[@]} "(objectcategory=group)" samaccountname | grep sAMAccountName.* | awk -F " " '{print substr($0, index($0,$2))}'

echo "=====[WSUS Exist Check]====="
echo "WARNING: WSUS not guaranteed to be in LDAP"
${Command[@]} "(&(objectClass=serviceConnectionPoint)(keywords=Windows Server Update Services))" cn serviceBindingInformation distinguishedName | grep -v refldap

echo "=====[DMSA - To fix]====="
${Command[@]} "(objectclass=msDS-DelegatedManagedServiceAccount)" name msDS-GroupMSAMembership msDS-ManagedAccountPrecededByLink | grep -v refldap

echo "=====[GMSA - To expand later]====="
${Command[@]} "(objectClass=msDS-GroupManagedServiceAccount)" name | grep -v refldap
${Command[@]} "(PrincipalsAllowedToRetrieveManagedPassword=*)" name | grep -v refldap

echo "=====[Managed Service Accounts]====="
${Command[@]} "(objectClass=msDS-ManagedServiceAccount)" name | grep -v refldap

echo "=====[Member of the protected users group - To fix ]====="
echo "Accounts cannot be delegated"
echo "Forces Kerberos authentication (NTLM auth disabled)"
echo "Reduces credential lifetime (e.g. TGT lifetime is shortened to 4 hours)"
echo "Prevents caching of plaintext credentials or weaker hashes"
echo ""
${Command[@]} "(&(objectClass=group)(cn=Protected Users))" member | grep member

echo "=====[No Delegation]====="
echo "Accounts cannot be delegated - No S4U for example"
${Command[@]} "(userAccountControl:1.2.840.113556.1.4.803:=1048576)" samaccountname | grep samaccountname

echo "=====[Smart Card Required for Auth]====="
echo "Users must use a smart card to sign into the network"
${Command[@]} "(userAccountControl:1.2.840.113556.1.4.803:=262144)" name | grep name

echo "=====[LDAP Descriptions - Saved to LDAPDescriptions]====="
echo ""
${Command[@]} "(&(objectCategory=*)(description=*))" dn description | grep -E "dn|description"   | awk '{print} /^description:/ {print ""}' > LDAPDescriptions.txt

echo "=====[MAQ]====="
echo "Number of computer accounts that your account can create. Note: other policies can also prevent account creation, double check."
${Command[@]} "(ms-DS-MachineAccountQuota=*)" ms-ds-machineaccountquota | grep ms-DS-MachineAccountQuota

echo "=====[Domain GPOs]====="
${Command[@]} "(objectCategory=groupPolicyContainer)" displayname gpcfilesyspath | grep -E "display|gPCFileSysPath" | awk '{print} /^gPCFileSysPath:/ {print ""}'

echo "=====[Deny Policies - To add]====="

echo "=====[GPOs Applied to current user]====="

echo "=====[Dangerous Attributes]====="
echo "Need to look into the format of each, belive its in UTF-8 format"
echo ""
echo "Users with the 'userPassword' attribute"
${Command[@]} "(UserPassword=*)" name userpassword | grep -v refldap
echo "Users with the 'unicodePwd' attribute"
${Command[@]} "(unicodePwd=*)" name unicodepwd | grep -v refldap
echo "Users with the 'unixUserPassword' attribute"
${Command[@]} "(unixUserPassword=*)" name unixuserpassword | grep -v refldap
echo "Users with the 'msSFU30Password' attribute"
${Command[@]} "(msSFU30Password=*)" name mssfu30password | grep -v refldap
echo "Users with the 'orclCommonAttribute' attribute"
${Command[@]} "(orclCommonAttribute=*)" name orclcommonattribute | grep -v refldap
echo "Users with the 'defender-tokenData' attribute"
${Command[@]} "(defender-tokenData=*)" name defender-tokendata | grep -v refldap
echo "Users with the 'dBCSPwd' attribute"
${Command[@]} "(dBCSPwd=*)" name dbcspwd | grep -v refldap

echo "=====[Kerberoastable Accounts]====="
echo ""
${Command[@]} "(&(objectCategory=user)(servicePrincipalname=*))" name serviceprincipalname | grep -E "name|servicePrincipalName"

echo "=====[ASRepRoast Accounts]====="
${Command[@]} "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" name | grep name

echo "=======[ADCS]=========="
ldapsearch -LLL -x -H $LDAPv://$DC:$LDAPport -D $USER -w $PASS -b "CN=Configuration,$DomainParsed" "(objectClass=pKIEnrollmentService)" dnshostname displayname mspki-enrollment-servers certificatetemplates | grep -v refldap

echo "=======[LDAP Sec]=========="
nxc ldap dcs.txt | grep -E "signing|binding"

echo "=======[Unconstrained Delegation]=========="
echo "Machines / users that can impersonate any domain user domain wide"
${Command[@]} "(userAccountControl:1.2.840.113556.1.4.803:=524288)" name | grep name

echo "=======[Constrained Delegation]=========="
echo "Machines / users that can impersonate any domain user on specified host/service"
${Command[@]} "(msds-allowedtodelegateto=*)" name msds-allowedtodelegateto

echo "=======[kerberosconstrainedDelegation - to add]=========="
# https://github.com/PyroTek3/Misc/blob/main/Get-ADKerberosDelegation.ps1

echo "
=======[Hosts with the RBCD attribute]=========="

git clone -q https://github.com/Kahvi-0/pyDescribeNTSecurityDescriptor.git
cd pyDescribeNTSecurityDescriptor
python -m venv venv
source venv/bin/activate
pip install -q --upgrade "sectools>=1.5.1"
pip install -q -r requirements.txt

${Command[@]} "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" dn name msDS-AllowedToActOnBehalfOfOtherIdentity | awk '
  /^dn:/ { dn=$0; next }
  /^name:/ { name=$2; next }
  /^msDS-AllowedToActOnBehalfOfOtherIdentity::/ {
      # start of value
      val = substr($0, index($0,"::")+3)
      # continuation lines start with a space
      while ((getline nextline) > 0 && nextline ~ /^ /) {
          val = val substr(nextline, 2)
      }
      print name, val
  }
' >  rbcd_values.txt

while read -r target b64; do
  echo " ===== Hosts With RBCD Rights to $target ====="
  echo $b64 > descriptor.txt
  SIDS=($(python3 DescribeNTSecurityDescriptor.py -v descriptor.txt --summary | grep -oP "S-1[0-9-]+"))
  for sid in "${SIDS[@]}"; do
    ${Command[@]} "(objectSid=$sid)" sAMAccountName dNSHostName | grep -E 'sAMAccountName|dNSHostName'
    echo ""
  done
  echo ""
done < rbcd_values.txt

deactivate
rm rbcd_values.txt descriptor.txt
cd ..
chmod -R u+rw pyDescribeNTSecurityDescriptor
rm -r pyDescribeNTSecurityDescriptor
#Debug
#${Command[@]} "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" dn name msDS-AllowedToActOnBehalfOfOtherIdentity

echo "=======[LAPS]=========="
${Command[@]} "(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))" name

echo "=======[SCCM - To Fix]=========="
${Command[@]} "(objectClass=mSSMSManagementPoint)" dnshostname mssmssitecode name

echo "=======[MSSQL]=========="
echo "Not perfect, computer accounts based off name"
${Command[@]} "(&(objectCategory=computer)(Name=*SQL*))" name

echo "=======[DNS Permissions - To Add]=========="

echo "=======[Obsolete host enumeration]=========="
echo "Hosts pulled from LDAP"
${Command[@]} "(objectCategory=computer)" cn operatingSystem | grep -B1 -E "Windows XP|Windows 7|Windows 8|Windows Server 2003|Windows Server 2008|Windows Server 2012|Windows Vista|Windows 2000| Windows 10"

echo -e "${GREEN}=======[Password Policies]==========${NC}"

IFS=$'\n'  SMBS=($(smbclient //$DC/SYSVOL -U "$USER%$PASS" -c "recurse; ls" \
  | awk '
    # Directory header line → remember current dir
    /^[\\]/ {
        dir=$0
        next
    }

    # File line where filename is exactly GptTmpl.inf
    /^[[:space:]]+GptTmpl\.inf[[:space:]]/ {
        print dir
        print $0
    }
  ' | awk '
/^[\\]/ { dir=$0; next }        # If line starts with "\" → save it
/^[[:space:]]+GptTmpl\.inf/ {   # If file line contains GptTmpl.inf
    print dir "\\" $1            # Append filename to directory path
}
' ))
for file in $(cat GPOPaths.txt); do
  GUID=$(echo $file | grep -oE "\{.*}")
  ${Command[@]} "(objectCategory=groupPolicyContainer)" dn displayname | grep -A2 $GUID | grep displayName
  smbclient //$DC/SYSVOL -U "$USER%$PASS" -c "get \"$file\" -" |  iconv -f UTF-16LE -t UTF-8 | grep -E 'Bad|Password|LockoutDuration|ResetLockout'
echo ""
done

#ldapsearch -LLL -x -H ldap://10.10.10.2:389 -D 'lab\Administrator' -w '' -b "DC=lab,DC=local" "(objectCategory=groupsPolicyContainer)" dn displayname | grep $GUID
