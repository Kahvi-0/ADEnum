#!/usr/bin/env bash

set -u

usage() {
    echo "Usage: $0 <targets_file>"
    exit 1
}

curl_code() {
    local url="$1"
    local code
    code="$(curl -k -sS -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "$url" 2>/dev/null)"

    if [[ $? -ne 0 || ! "$code" =~ ^[0-9]{3}$ ]]; then
        printf "000"
        return
    fi

    printf "%s" "$code"
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
    "/sms_mp/.sms_aut?MPLIST"
    "/CCM_System"
    "/CCM_system_WindowsAuth"
    "/CCM_System_AltAuth"
    "/CCM_System_TokenAuth"
    "/AdminService/v1.0/"
    "/AdminService/wmi/"
)

while IFS= read -r host; do
    host_has_match=0
    adcs_output=""
    wsus_output=""
    sccm_output=""

    # ADCS
    http_adcs="$(curl_code "http://$host/certsrv/certfnsh.asp")"
    https_adcs="$(curl_code "https://$host/certsrv/certfnsh.asp")"

    if [[ "$http_adcs" == "401" ]]; then
        adcs_output+="    - HTTP  /certsrv/certfnsh.asp -> $http_adcs"$'\n'
        host_has_match=1
    fi
    if [[ "$https_adcs" == "401" ]]; then
        adcs_output+="    - HTTPS /certsrv/certfnsh.asp -> $https_adcs"$'\n'
        host_has_match=1
    fi

    # WSUS
    for path in "${wsus_paths[@]}"; do
        code_http="$(curl_code "http://$host:8530$path")"
        code_https="$(curl_code "https://$host:8531$path")"

        if [[ "$code_http" != "000" && "$code_http" != "404" && "$code_http" != "503" ]]; then
            wsus_output+="    - HTTP  :8530$path -> $code_http"$'\n'
            host_has_match=1
        fi

        if [[ "$code_https" != "000" && "$code_https" != "404" && "$code_https" != "503" ]]; then
            wsus_output+="    - HTTPS :8531$path -> $code_https"$'\n'
            host_has_match=1
        fi
    done

    # SCCM
    for proto in http https; do
        for path in "${sccm_paths[@]}"; do
            code="$(curl_code "$proto://$host$path")"

            if [[ "$code" != "000" && "$code" != "404" ]]; then
                sccm_output+="    - ${proto^^} $path -> $code"$'\n'
                host_has_match=1
            fi
        done
    done

    if [[ "$host_has_match" -eq 1 ]]; then
        echo "$host - AD Web Service Checks"

        if [[ -n "$adcs_output" ]]; then
            echo "  ADCS checks"
            printf "%s" "$adcs_output"
        fi

        if [[ -n "$wsus_output" ]]; then
            echo "  WSUS checks"
            printf "%s" "$wsus_output"
        fi

        if [[ -n "$sccm_output" ]]; then
            echo "  SCCM checks"
            printf "%s" "$sccm_output"
        fi

        echo
    fi
done < ADWebServicesHosts.txt
