#!/bin/bash

#Example passpULL.sh 'user' 'password' 'dcs.txt' 'domain.local' 'distingushed name' 
#passpULL.sh 'user' 'password' 'dcs.txt' 'domain.local' 'CN=PENTEST,OU=USERS,OU=test,DC=lab,DC=LOCAL' 
#req: manspider
#Default pwd 

echo "=============================="
echo "Checking default domain policy"
echo "=============================="

nxc smb $3  -u $1 -p $2 --pass-pol  | grep -Ev '\+|\*' |awk -F ' ' 'BEGIN { ORS=" " }; {print$2" "$5" "$6" "$7" "$8" "$9" "$10" "$11" "$12" "$13} {printf"\n"}'

#policy Other policy defined pwd policies
echo "=================================================="
echo "Searching Domain Controllers for password policies"
echo "=================================================="
echo ""

manspider $3 -c LockoutBadCount Threshold Password -e .inf -d $4 -u $1 -p $2 -n | grep -vE 'MANSPIDER command|Using.*threads|Searching by|Skipping files'

# Fine grain pwd policies

echo ""
echo "==========================================="
echo "LDAP query for fine grain password policies"
echo "==========================================="
echo ""

echo $4 | awk -F '.' 'BEGIN { ORS=""}; {print"dc="$1}{print","}{print"dc="$2}{printf"\n"}' > base.txt 
base=$(cat base.txt)
dcs=$(cat dcs.txt)

for i in $dcs; do 
echo "checking $i"
ldapsearch -x -b $base -H ldap://$i:389/ -D $5 -w $2 'msds-psoapplied=*' | grep -E 'givenName|cn|member|msDS-PSOApplied'
done
# can we read the fine grained pwd policy ?

echo ""
echo "==========================================="
echo "Checking if we can read the fine grain password policies" 
echo "==========================================="
echo ""

ldapsearch -x -b $base -H ldap://$i:389/  -D $5 -w $2 'msDS-LockoutThreshold=*' | grep -E 'cn:|msDS*.Password|Lockout|PSOAppliesTo'
rm base.txt
