rm ADWebServicesCheck*
nmap -sT -Pn --resolve-all --open -p 80,443,8530 -iL $1 -oA ADWebServicesCheck >/dev/null 2>&1
cat ADWebServicesCheck.gnmap | grep Host | awk -F " " '{print$2}' | sort -u | sed '/^$/d' > ADWebServicesHosts-temp.txt
cat ADWebServicesCheck.gnmap | grep Host | awk -F " " '{print$3}' | sed 's|[(),]||g' | sort -u | sed '/^$/d' >> ADWebServicesHosts-temp.txt
cat ADWebServicesHosts-temp.txt | sort -u > ADWebServicesHosts.txt

for i in $(cat ADWebServicesHosts.txt); do 
    #Looking for ADCS endpoints
    HTTP_ADCS=$(curl -s -o /dev/null -w  "%{http_code}" http://$i/certsrv/certfnsh.asp)
    HTTPS_ADCS=$(curl -s -o /dev/null -w  "%{http_code}" https://$i/certsrv/certfnsh.asp)
    #Looking for WSUS endpoints
    HTTP_WSUS=$(curl -s -o /dev/null -w "%{http_code}" http://$i:8530/ClientWebService/SimpleAuth.asmx)
    HTTP_WSUS1=$(curl -s -o /dev/null -w "%{http_code}" http://$i:8530/ClientWebService/Client.asmx)
    HTTP_WSUS2=$(curl -s -o /dev/null -w "%{http_code}" http://$i:8530/ApiRemoting30/WebServices.asmx)
    #Looking for SCCM endpoints
    HTTP_SCCM=$(curl -s -o /dev/null -w "%{http_code}" http://$i/sms_mp/.sms_aut?MPLIST)
    HTTP_SCCM1=$(curl -s -o /dev/null -w "%{http_code}" http://$i/CCM_System)
    HTTP_SCCM2=$(curl -s -o /dev/null -w "%{http_code}" http://$i/CCM_system_WindowsAuth)
    HTTP_SCCM3=$(curl -s -o /dev/null -w "%{http_code}" http://$i/CCM_System_AltAuth)
    HTTP_SCCM4=$(curl -s -o /dev/null -w "%{http_code}" http://$i/CCM_System_TokenAuth)
    HTTP_SCCM5=$(curl -s -o /dev/null -w "%{http_code}" http://$i/AdminService/v1.0/)
    HTTP_SCCM6=$(curl -s -o /dev/null -w "%{http_code}" http://$i/AdminService/wmi/)

    HTTPS_SCCM=$(curl -s -o /dev/null -w "%{http_code}" https://$i/sms_mp/.sms_aut?MPLIST)
    HTTPS_SCCM1=$(curl -s -o /dev/null -w "%{http_code}" https://$i/CCM_System)
    HTTPS_SCCM2=$(curl -s -o /dev/null -w "%{http_code}" https://$i/CCM_system_WindowsAuth)
    HTTPS_SCCM3=$(curl -s -o /dev/null -w "%{http_code}" https://$i/CCM_System_AltAuth)
    HTTPS_SCCM4=$(curl -s -o /dev/null -w "%{http_code}" https://$i/CCM_System_TokenAuth)
    HTTPS_SCCM5=$(curl -s -o /dev/null -w "%{http_code}" https://$i/AdminService/v1.0/)
    HTTPS_SCCM6=$(curl -s -o /dev/null -w "%{http_code}" https://$i/AdminService/wmi/)
    
    #Result logic
    # ADCS Web
    if [ "$HTTP_ADCS" -eq 401 ]; then
    	echo "$i - ADCS Web over HTTP - Got 401 Error"
    fi
    if [ "$HTTPS_ADCS" -eq 401 ]; then
    	echo "$i - ADCS Web over HTTPS - Got 401 Error"
    fi    

    # WSUS Web
    if [ "$HTTP_WSUS" -nq 404 ]; then
    	echo "$i - WSUS Web over HTTP - $HTTP_WSUS Returned"
    fi
    if [ "$HTTP_WSUS1" -nq 404 ]; then
    	echo "$i - WSUS Web over HTTP - $HTTP_WSUS1 Returned"
    fi
    if [ "$HTTP_WSUS2" -nq 404 ]; then
    	echo "$i - WSUS Web over HTTP - $HTTP_WSUS2 Returned"
    fi

    # SCCM Web    
    if [ "$HTTP_SCCM" -nq 404 ]; then
    	echo "$i - SCCM Web over HTTP - $HTTP_SCCM Returned"
    fi
    if [ "$HTTPS_SCCM" -nq 404 ]; then
    	echo "$i - SCCM Web over HTTPS - $HTTPS_SCCM Returned"
    fi    

    if [ "$HTTP_SCCM1" -nq 404 ]; then
    	echo "$i - SCCM Web over HTTP - $HTTP_SCCM1 Returned"
    fi
    if [ "$HTTPS_SCCM1" -nq 404 ]; then
    	echo "$i - SCCM Web over HTTPS - $HTTPS_SCCM1 Returned"
    fi    

    if [ "$HTTP_SCCM2" -nq 404 ]; then
    	echo "$i - SCCM Web over HTTP - $HTTP_SCCM2 Returned"
    fi
    if [ "$HTTPS_SCCM2" -nq 404 ]; then
    	echo "$i - SCCM Web over HTTPS - $HTTPS_SCCM2 Returned"
    fi    

    if [ "$HTTP_SCCM3" -nq 404 ]; then
    	echo "$i - SCCM Web over HTTP - $HTTP_SCCM3 Returned"
    fi
    if [ "$HTTPS_SCCM3" -nq 404 ]; then
    	echo "$i - SCCM Web over HTTPS - $HTTPS_SCCM3 Returned"
    fi    

    if [ "$HTTP_SCCM4" -nq 404 ]; then
    	echo "$i - SCCM Web over HTTP - $HTTP_SCCM4 Returned"
    fi
    if [ "$HTTPS_SCCM4" -nq 404 ]; then
    	echo "$i - SCCM Web over HTTPS - $HTTPS_SCCM4 Returned"
    fi    

    if [ "$HTTP_SCCM5" -nq 404 ]; then
    	echo "$i - SCCM Web over HTTP - $HTTP_SCCM5 Returned"
    fi
    if [ "$HTTPS_SCCM5" -nq 404 ]; then
    	echo "$i - SCCM Web over HTTPS - $HTTPS_SCCM5 Returned"
    fi    

    if [ "$HTTP_SCCM6" -nq 404 ]; then
    	echo "$i - SCCM Web over HTTP - $HTTP_SCCM6 Returned"
    fi
    if [ "$HTTPS_SCCM6" -nq 404 ]; then
    	echo "$i - SCCM Web over HTTPS - $HTTPS_SCCM6 Returned"
    fi    
    
done

