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
    "/sms_mp/.sms_aut?MPLIST"
    "/CCM_System"
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

        for path in "${sccm_paths[@]}"; do
            sccm_url="$proto://$host:$port$path"
            code="$(curl_code "$sccm_url")"

            if ! is_ignored_code "$code"; then
                sccm_output+="    - $sccm_url -> $code"$'\n'
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
