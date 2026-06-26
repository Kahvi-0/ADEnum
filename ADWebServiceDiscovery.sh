#!/usr/bin/env bash

set -u

RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
BLUE=$(tput setaf 4)
PURPLE=$(tput setaf 5)
YELLOW=$(tput setaf 3)
RESET=$(tput sgr0)

usage() {
    echo "Usage: $0 <targets_file>"
    exit 1
}

curl_status() {
    local url="$1"
    local status
    status="$(curl -sIk "$url" | awk 'NR==1 {print substr( $0, index( $0, $3))}')"


    printf "%s" "$status"
}

curl_code() {
    local url="$1"
    local code
    code="$(curl -k -sS -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "$url" 2>/dev/null)"
    

    if [[ $? -ne 0 || ! "$code" =~ ^[0-9]{3}$ ]]; then
        printf "000"
        return
    fi

    printf "%s" "$code "
}

is_ignored_code() {
    local code="$1"
    local ignored

    for ignored in "${ignore_codes[@]}"; do
        [[ "$code" == "$ignored" ]] && return 0
    done

    return 1
}

targets_file="${1:-}"
[[ -n "$targets_file" && -f "$targets_file" ]] || usage

rm -f ADWebServicesCheck.gnmap ADWebServicesCheck.nmap ADWebServicesCheck.xml ADWebServicesHosts-temp.txt ADWebServicesHosts.txt

nmap -sT -Pn --resolve-all --open -p 80,443,8530 -iL "$targets_file" -oA ADWebServicesCheck >/dev/null 2>&1

awk '/Host: / { print $2; gsub(/[(),]/, "", $3); print $3 }' ADWebServicesCheck.gnmap | sed '/^$/d' | sort -u > ADWebServicesHosts.txt

if [[ ! -s ADWebServicesHosts.txt ]]; then
    echo "No responsive hosts found in scan output."
    exit 0
fi

wsus_paths=(
    "/ClientWebService/SimpleAuth.asmx"
    "/ClientWebService/Client.asmx"
    "/ApiRemoting30/WebServices.asmx"
)

sccm_paths=(
    "/CCM_System"
    "/ccm_system/request"
    "/ccm_system/ccm_post"
    "/CCM_system_WindowsAuth"
    "/CCM_System_AltAuth"
    "/CCM_System_TokenAuth"
    "/AdminService/v1.0/"
    "/AdminService/wmi/"
)

ignore_codes=(000 301 302 404 500 502 503)

while IFS= read -r host; do
    host_has_match=0
    adcs_output=""
    wsus_output=""
    sccm_output=""

    # ADCS
    adcs_http_url="http://$host:80/certsrv/certfnsh.asp"
    adcs_https_url="https://$host:443/certsrv/certfnsh.asp"
    http_adcs="$(curl_code "$adcs_http_url")"
    https_adcs="$(curl_code "$adcs_https_url")"

    if [[ "$http_adcs" == "401" ]]; then
        adcs_output+="    - $adcs_http_url -> $http_adcs"$'\n'
        host_has_match=1
    fi
    if [[ "$https_adcs" == "401" ]]; then
        adcs_output+="    - $adcs_https_url -> $https_adcs"$'\n'
        host_has_match=1
    fi

    # WSUS
    for path in "${wsus_paths[@]}"; do
        wsus_http_url="http://$host:8530$path"
        wsus_https_url="https://$host:8531$path"
        code_http="$(curl_code "$wsus_http_url")"
        code_https="$(curl_code "$wsus_https_url")"

        if ! is_ignored_code "$code_http"; then
            wsus_output+="    - $wsus_http_url -> $code_http"$'\n'
            host_has_match=1
        fi

        if ! is_ignored_code "$code_https"; then
            wsus_output+="    - $wsus_https_url -> $code_https"$'\n'
            host_has_match=1
        fi
    done

    # SCCM
    for proto in http https; do
        if [[ "$proto" == "http" ]]; then
            port=80
        else
            port=443
        fi

        for path in "/sms_mp/.sms_aut?MPLIST"; do
            sccm_url="$proto://$host:$port$path"
            code="$(curl_code "$sccm_url")"
            status="$(curl_status $sccm_url)"
            MPCheck="$(curl -sk $sccm_url | grep MPList)"
            message="$(echo 'HTTPS mTLS Mode Enforced')"
	    sccmmode=$(curl -ski "$sccm_url" | grep -o SSLState.............)
	    	    
            if ! is_ignored_code "$code"; then
            	if [[ "$code" -eq "200" && $MPCheck = *"MPList"* ]]; then
		        sccm_output+="     "$'\n'
		        sccm_output+="    ${RED}Management Point Metadata"$'\n'
		        sccm_output+="    Non mTLS traffic enforced for this endpoint${RESET}"$'\n'
		        sccm_output+="    $sccm_url -> $code $status"$'\n'
		        sccm_output+="    $MPCheck -> $code $status"$'\n'
		        sccm_output+="     "$'\n'
		        host_has_match=1
		        
		        if [[ "$sccmmode" == *"0"* ]]; then
		           sccm_output+="  ${GREEN}[+] Site allows HTTP or has eHTTP - Secure from Alternate Auth Exploit${RESET}"$'\n'

		       # Capture 33, 63, and any hybrid variations (like 31, 35, 47) that imply HTTPS/Token enforcement
		       elif [[ "$sccmmode" == *"33"* || "$sccmmode" == *"63"* || "$sccmmode" == *"31"* || "$sccmmode" == *"35"* || "$sccmmode" == *"47"* ]]; then
		           sccm_output+="  ${RED}[!] Site configured with strict HTTPS/Token Enforcement (SSLState: $sccmmode)${RESET}"$'\n'
		           sccm_output+="  ${RED}[!] Standard framework paths require mTLS/Valid Certificates.${RESET}"$'\n'
		           sccm_output+="  ${RED}[!] High Risk: May be vulnerable to Alternate Authentication Exploit if endpoints are exposed (--altauth)${RESET}"$'\n'

		# Catch-all for any rare bitmask configurations you haven't explicitly hardcoded
		       else
		           sccm_output+="  ${YELLOW}[?] Detected uncommon SSLState Value: $sccmmode${RESET}"$'\n'
		           sccm_output+="  ${YELLOW}[?] Manual verification of the /ccm_system_altauth/ path required.${RESET}"$'\n'
		       fi
		        
		elif [[ $status == *"Client certificate required"* ]]; then

		        sccm_output+="     "$'\n'
		        sccm_output+="    - $sccm_url -> $code $status"$'\n' 
		        sccm_output+="        ${RED}$message${RESET}   "$'\n' 
		        sccm_output+="     "$'\n' 
		else 
		        sccm_output+="    - $sccm_url -> $code $status"$'\n'
		        host_has_match=1
		fi
            fi
        done

   
        for path in "/ccm_system_altauth/request"; do
            sccm_url="$proto://$host:$port$path"
            code="$(curl_code "$sccm_url")"
            status="$(curl_status $sccm_url)"
            message="$(echo 'HTTPS mTLS Mode Enforced')"

            if ! is_ignored_code "$code"; then
            	if [ "$code" -eq "200" ]; then
		        sccm_output+="     "$'\n'
		        sccm_output+="    ${RED}Alternate Authentication Endpoint Enabled!"$'\n'
		        sccm_output+="    Exploit with SCCMSecrets --altauth flag if site is in HTTPS-Only${RESET}"$'\n'
		        sccm_output+="    $sccm_url -> $code $status"$'\n'
		        sccm_output+="    $MPCheck -> $code $status"$'\n'
		        sccm_output+="     "$'\n'
		        host_has_match=1
		elif [[ $status == *"Client certificate required"* ]]; then

		        sccm_output+="     "$'\n'
		        sccm_output+="    ${GREEN}Alternate Authentication Endpoint Prevented${RESET}"$'\n'
		        sccm_output+="    - $sccm_url -> $code $status"$'\n' 
		        sccm_output+="        ${RED}$message${RESET}   "$'\n' 
		        sccm_output+="     "$'\n' 
		else 
		        sccm_output+="     "$'\n'
		        sccm_output+="    ${GREEN}Alternate Authentication Endpoint NOT Enabled :(${RESET}"$'\n'
		        sccm_output+="    - $sccm_url -> $code $status"$'\n'
		        sccm_output+="     "$'\n'
		        host_has_match=1
		        
		fi
            fi
        done

        for path in "${sccm_paths[@]}"; do
            sccm_url="$proto://$host:$port$path"
            code="$(curl_code "$sccm_url")"
            status="$(curl_status "$sccm_url")"

            if ! is_ignored_code "$code"; then
                sccm_output+="    - $sccm_url -> $code $status"$'\n'
                host_has_match=1
            fi
        done
    done

    if [[ "$host_has_match" -eq 1 ]]; then
        echo "${PURPLE}$host - AD Web Service Checks${RESET}"

        if [[ -n "$adcs_output" ]]; then
            echo ""
            echo "  ${BLUE}ADCS checks${RESET}"
            printf "%s" "$adcs_output"
        fi

        if [[ -n "$wsus_output" ]]; then
            echo ""
            echo "  ${BLUE}WSUS checks${RESET}"
            printf "%s" "$wsus_output"
        fi

        if [[ -n "$sccm_output" ]]; then
            echo ""
            echo "  ${BLUE}SCCM checks${RESET}"
            printf "%s" "$sccm_output"
        fi

        echo
    fi
done < ADWebServicesHosts.txt
