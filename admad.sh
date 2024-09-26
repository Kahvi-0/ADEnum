#!/bin/bash

# Target ideally DC
#Use:
# ./admad.sh [target] [username] [password]

WHITE="\e[97m"
BLUE="\e[34m"
RED="\e[31m"
GREEN="\e[32m"
ENDCOLOUR="\e[0m"

target=$1
user=$2
pass=$3

# Check if provided credentials are valid
check=$(nxc smb $target -u $2 -p $3 | grep -o '\[+\]')
if [[ $check == '[+]' ]]
then
echo " "
else
echo -e "${RED}Credentials were not valid${ENDCOLOUR}"
exit
fi

# Password policy
echo -e "${GREEN}Getting password policy ${ENDCOLOUR}"
echo " "
nxc smb $target -u $2 -p $3 --pass-pol | tee  passpol.txt
echo "-----------------------------------------------------------------------------------------------"

echo -e "${GREEN}Getting Machine Account Quota${ENDCOLOUR}"
echo " "
echo -e "${BLUE}Useful when you need to create a machine account for attacks such as RBCD/S4U ${ENDCOLOUR}"
echo " "
nxc ldap $target -u $2 -p $3 -M maq
echo "-----------------------------------------------------------------------------------------------"

echo -e "${GREEN}Checking for ADCS server${ENDCOLOUR}"
echo " "
echo -e "${BLUE}Use a tool such as certipy to check for ADCS vulns${ENDCOLOUR}"
echo ""
echo -e "${WHITE}If none are returned, it is still recommended to check using an alt method.${ENDCOLOUR}"
echo ""
nxc ldap $target -u $2 -p $3 -M adcs
echo "-----------------------------------------------------------------------------------------------"

echo -e "${GREEN}Getting all accessible DCs based on the provided target${ENDCOLOUR}"
echo " "
echo -e "${BLUE}Double check for connection errors here and any possible missing DCs${ENDCOLOUR}"
echo " "
nxc ldap $target -u $2 -p $3 --dc-list | tee dchosts.txt
cat dchosts.txt |  grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u | tee dcs.txt
echo "-----------------------------------------------------------------------------------------------"

echo -e "${GREEN}Getting all DNS servers according to DC${ENDCOLOUR}"
echo " "
nxc ldap $target -u $2 -p $3 -M enum_dns | tee ADDNS.txt
echo "-----------------------------------------------------------------------------------------------"

echo -e "${GREEN}Getting all accounts where Pwd not required${ENDCOLOUR}"
echo " "
nxc ldap $target -u $2 -p $3 --password-not-required | tee Pwd-Not-Required.txt
echo "-----------------------------------------------------------------------------------------------"

echo -e "${GREEN}Getting all Admins according to DC${ENDCOLOUR}"
echo " "
nxc ldap $target -u $2 -p $3 --admin-count | tee AD-AdminCount.txt
echo "-----------------------------------------------------------------------------------------------"

echo -e "${GREEN}Checking if domain controllers have SMB Siging disabled${ENDCOLOUR}"
nxc smb ./dcs.txt | awk -F "("  '{ ORS=" " };{print$2}{print$4}{printf"\n"}' | grep -E 'signing|name'

echo -e "${GREEN}Checking for LDAP signing${ENDCOLOUR}" 
echo " "
echo -e "${BLUE}If not enforced, could be abused for RBCD/S4U attacks${ENDCOLOUR}"
echo "" 
filename=$(cat dcs.txt)
for i in $filename; do
nxc ldap $i -u $2 -p $3 -M ldap-checker
done
echo "-----------------------------------------------------------------------------------------------"

echo -e "${GREEN}Checking for NoPac,zerologon,printnightmare on domain controllers${ENDCOLOUR}" 
echo "" 
filename=$(cat dcs.txt)
for i in $filename; do
	nxc smb $i -u '' -p '' -M zerologon
	nxc smb $i -u $2 -p $3 -M nopac
	nxc smb $i -u $2 -p $3 -M printnightmare
done
echo "-----------------------------------------------------------------------------------------------"

echo -e "${GREEN}Hosts Trusted For Delegation${ENDCOLOUR}"
echo " "
echo -e "Machine accounts that can impersonate any user. Could abuse if you could access"
echo " "
nxc ldap $target -u $2 -p $3 --trusted-for-delegation
echo "-----------------------------------------------------------------------------------------------"

echo -e "${GREEN}Dumping all Domain Users${ENDCOLOUR}" 
echo -e "${BLUE}Output saved to DomainUsers.txt${ENDCOLOUR} "
nxc smb $target -u $2 -p $3 --users > i.txt && cat i.txt | sort -u | awk -F " " '{print$5}' | grep -vE '[*]|[+]|-Username-' > DomainUsers.txt && rm i.txt
echo "-----------------------------------------------------------------------------------------------"

echo -e "${GREEN}Dumping LDAP descriptions${ENDCOLOUR}"
echo -e "${BLUE}Output saved to userdescriptions.txt${ENDCOLOUR}" 
nxc ldap $target -u $2 -p $3 -M get-desc-users >  userdescriptions.txt 
echo "-----------------------------------------------------------------------------------------------"
