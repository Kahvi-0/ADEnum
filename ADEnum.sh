#!/bin/bash

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
NC="\e[0m"

usage() {
    echo ""
    echo -e "${RED}USAGE:${NC}"

    echo "ADEnum.sh [-u domain\user] [-p password] [-d domain] [-t dc] [-v LDAP/LDAPS] [-l LDAP port] "
    echo ""
    echo -e "Required Options:\n"
    echo -e "-u 	Username - Format (Shortform for domain): lab\Admin"
    echo -e "-p		Password"
    echo -e "-d		Domain - Format: test.lab"
    echo -e "-t 	Domain controller - Format: dc1, 10.10.10.1, dc1.lab.local\n"

    echo -e "Optinal Options:\n"
    echo -e "-l		LDAP port"
    echo -e "-v		LDAP type - LDAP or LDAPS"
    echo -e "-k		Use Kerberos authenticaiton\n"

    echo 'example: ./ADEnum.sh -u "LAB\Administrator" -p Password123 -d lab.local -t dc2'
    exit 1
}

USER=""
PASS=''
DC=""
Domain=""
LDAPv=ldap
LDAPport=389

while getopts ":u:p:v:d:t:l:kh" opt; do
  case $opt in
    u) USER="$OPTARG" ;;
    p) PASS="$OPTARG" ;;
    v) LDAPv="$OPTARG" ;;
    d) Domain="$OPTARG" ;;
    t) DC="$OPTARG" ;;
    l) LDAPport="$OPTARG" ;;
    k) Kerberos=1 ;;
    h) usage && exit;;
    \?) echo "Invalid option: -$OPTARG"; usage ;;
    :) echo "Option -$OPTARG requires an argument."; usage ;;
  esac
done

DomainParsed=$(echo "$Domain" | awk -F. '{for(i=1;i<=NF;i++) printf "DC=%s%s", $i, (i<NF?",":"")}')

#Kerberos

if [[ $Kerberos -ne 1 ]]; then
     echo "Not Using Kerberos Authentication"
     Command=(ldapsearch -LLL -x -H $LDAPv://$DC:$LDAPport -D $USER -w $PASS -b "$DomainParsed" -E pr=1000/noprompt)
     SMBClient=(smbclient //$DC/SYSVOL -U "$USER%$PASS")
else
     echo "Using Kerberos Authentication"

     cat > /tmp/krb5_lab.conf << 'EOF'
[libdefaults]
  default_realm = LAB.LOCAL

[realms]
  LAB.LOCAL = {
   kdc = dc2.lab.local
  }
EOF

     export KRB5_CONFIG=/tmp/krb5_lab.conf
     UPPER=$(echo "$Domain" | tr '[:lower:]' '[:upper:]')
     STRIPPED="${USER#*\\}"
     echo $PASS | kinit $STRIPPED@$UPPER
     Command=(ldapsearch -LLL -Q -Y GSSAPI -H $LDAPv://$DC:$LDAPport -b "$DomainParsed" -E pr=1000/noprompt)
     SMBClient=(smbclient --use-kerberos=required //$DC/SYSVOL)
     echo ${Command[@]}
fi


shift $((OPTIND - 1))

# Checks if the first command succeeds or else it exits
${Command[@]} > /dev/null
if [[ $? -ne 0 ]]; then
    echo "LDAPSEARCH FAILED — exiting."
    usage
    exit 1
fi

echo -e "${GREEN}=====[Domain Controllers]=====${NC}"
${Command[@]} "(userAccountControl:1.2.840.113556.1.4.803:=8192)" name | grep name | awk -F " " '{print substr($0, index($0,$2))}' | tee dcs.txt

echo -e "${GREEN}=====[Domain Trusts - To fix]=====${NC}"
${Command[@]} "(objectClass=trustedDomain)" cn trustPartner trustDirection trustType trustAttributes flatName

echo -e "${GREEN}=====[Domain Trusts - Interdomain Trust]=====${NC}"
echo "INTERDOMAIN_TRUST_ACCOUNT - is a permit to TrustedDomain an account for a system domain that trusts other AD DOMAINs"
${Command[@]} "(userAccountControl:1.2.840.113556.1.4.803:=2048)" name | grep name

echo -e "${GREEN}=====[Domain Users - Saved to DomainUsers-AuthenticatedLDAP.txt]=====${NC}"
${Command[@]} "(objectClass=user)" sAMAccountName | grep sAMAccountName.* | awk -F " " '{print substr($0, index($0,$2))}' > DomainUsers-AuthenticatedLDAP.txt

echo -e "${GREEN}=====[Domain Users that do not require password- Saved to DomainUsers-NoPwdRequired.txt]=====${NC}"
${Command[@]} "(userAccountControl:1.2.840.113556.1.4.803:=32)" sAMAccountName | grep sAMAccountName | awk -F " " '{print substr($0, index($0,$2))}'

echo -e "${GREEN}=====[Domain Groups]=====${NC}"
${Command[@]} "(objectcategory=group)" samaccountname | grep sAMAccountName.* | awk -F " " '{print substr($0, index($0,$2))}'

echo -e "${GREEN}=====[WSUS Exist Check]=====${NC}"
echo "WARNING: WSUS not guaranteed to be in LDAP"
${Command[@]} "(&(objectClass=serviceConnectionPoint)(keywords=Windows Server Update Services))" cn serviceBindingInformation distinguishedName | grep -v refldap

echo -e "${GREEN}=====[DMSA - To fix]=====${NC}"
${Command[@]} "(objectclass=msDS-DelegatedManagedServiceAccount)" name msDS-GroupMSAMembership msDS-ManagedAccountPrecededByLink | grep -v refldap

echo -e "${GREEN}=====[GMSA - To expand later]=====${NC}"
${Command[@]} "(objectClass=msDS-GroupManagedServiceAccount)" name | grep -v refldap
${Command[@]} "(PrincipalsAllowedToRetrieveManagedPassword=*)" name | grep -v refldap

echo -e "${GREEN}=====[Managed Service Accounts]=====${NC}"
${Command[@]} "(objectClass=msDS-ManagedServiceAccount)" name | grep -v refldap

echo -e "${GREEN}=====[Member of the protected users group - To fix ]=====${NC}"
echo "Accounts cannot be delegated"
echo "Forces Kerberos authentication (NTLM auth disabled)"
echo "Reduces credential lifetime (e.g. TGT lifetime is shortened to 4 hours)"
echo "Prevents caching of plaintext credentials or weaker hashes"
echo ""
${Command[@]} "(&(objectClass=group)(cn=Protected Users))" member | grep member

echo -e "${GREEN}=====[No Delegation]=====${NC}"
echo "Accounts cannot be delegated - No S4U for example"
${Command[@]} "(userAccountControl:1.2.840.113556.1.4.803:=1048576)" samaccountname | grep samaccountname

echo -e "${GREEN}=====[Smart Card Required for Auth]=====${NC}"
echo "Users must use a smart card to sign into the network"
${Command[@]} "(userAccountControl:1.2.840.113556.1.4.803:=262144)" name | grep name

echo -e "${GREEN}=====[LDAP Descriptions - Saved to LDAPDescriptions]=====${NC}"
echo ""
${Command[@]} "(&(objectCategory=*)(description=*))" dn description | grep -E "dn|description"   | awk '{print} /^description:/ {print ""}' > LDAPDescriptions.txt

echo -e "${GREEN}=====[MAQ]=====${NC}"
echo "Number of computer accounts that your account can create. Note: other policies can also prevent account creation, double check."
${Command[@]} "(ms-DS-MachineAccountQuota=*)" ms-ds-machineaccountquota | grep ms-DS-MachineAccountQuota

echo -e "${GREEN}=====[Domain GPOs]=====${NC}"
${Command[@]} "(objectCategory=groupPolicyContainer)" displayname gpcfilesyspath | grep -E "display|gPCFileSysPath" | awk '{print} /^gPCFileSysPath:/ {print ""}'

echo -e "${GREEN}=====[Deny Policies - To add]=====${NC}"

echo -e "${GREEN}=====[GPOs Applied to current user - TO ADD]=====${NC}"
echo ""
echo -e "${GREEN}=====[Dangerous Attributes]=====${NC}"
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

echo -e "${GREEN}=====[Kerberoastable Accounts]=====${NC}"
echo ""
${Command[@]} "(&(objectCategory=user)(servicePrincipalname=*))" name serviceprincipalname | grep -E "name|servicePrincipalName"

echo -e "${GREEN}=====[ASRepRoast Accounts]=====${NC}"
${Command[@]} "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" name | grep name

echo -e "${GREEN}=======[ADCS]==========${NC}"
ldapsearch -LLL -x -H $LDAPv://$DC:$LDAPport -D $USER -w $PASS -b "CN=Configuration,$DomainParsed" "(objectClass=pKIEnrollmentService)" dnshostname displayname mspki-enrollment-servers certificatetemplates | grep -v refldap

echo -e "${GREEN}=======[LDAP Sec]==========${NC}"
nxc ldap dcs.txt | grep -E "signing|binding"

echo -e "${GREEN}=======[Unconstrained Delegation]==========${NC}"
echo "Machines / users that can impersonate any domain user domain wide"
${Command[@]} "(userAccountControl:1.2.840.113556.1.4.803:=524288)" name | grep name

echo -e "${GREEN}=======[Constrained Delegation]==========${NC}"
echo "Machines / users that can impersonate any domain user on specified host/service"
${Command[@]} "(msds-allowedtodelegateto=*)" name msds-allowedtodelegateto

echo -e "${GREEN}=======[kerberosconstrainedDelegation - to add]==========${NC}"
# https://github.com/PyroTek3/Misc/blob/main/Get-ADKerberosDelegation.ps1

echo -e "${GREEN}=======[Hosts with the RBCD attribute]==========${NC}"

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
  echo -e "${GREEN}===== Hosts With RBCD Rights to $target =====${NC}"
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

echo -e "${GREEN}=======[LAPS]==========${NC}"
${Command[@]} "(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))" name

echo -e "${GREEN}=======[SCCM - To Fix]==========${NC}"
${Command[@]} "(objectClass=mSSMSManagementPoint)" dnshostname mssmssitecode name

echo -e "${GREEN}=======[MSSQL]==========${NC}"
echo "Not perfect, computer accounts based off name"
${Command[@]} "(&(objectCategory=computer)(Name=*SQL*))" name

echo -e "${GREEN}=======[DNS Permissions - To Add]==========${NC}"

echo -e "${GREEN}=======[Obsolete host enumeration]==========${NC}"
echo "Hosts pulled from LDAP"
${Command[@]} "(objectCategory=computer)" cn operatingSystem |grep -B1 -E "Windows XP|Windows 7|Windows 8|Windows Server 2003|Windows Server 2008|Windows Server 2012|Windows Vista|Windows 2000| Windows 10"

echo -e "${GREEN}=======[Password Policies]==========${NC}"
IFS=$'\n'  SMBS=($(${SMBClient[@]} -c "recurse; ls" \
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

for file in "${SMBS[@]}"; do
  GUID=$(printf '%s\n' $file | grep -oE "\{.*}")
  ${Command[@]} "(objectCategory=groupPolicyContainer)" dn displayname | grep -A2 $GUID | grep displayName
  ${SMBClient[@]} -c "get \"$file\" -" | iconv -f UTF-16LE -t UTF-8//IGNORE 2>/dev/null | grep -E 'Bad|Password|LockoutDuration|ResetLockout'
echo ""
done
