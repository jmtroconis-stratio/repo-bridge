#!/usr/bin/env bash

# set -o nounset
set -o errexit
# set -x

############## Log checking
LOCAL_ERROR() { echo -e "ERROR: ${1-}" >&2 ; }
LOCAL_INFO()  { echo -e "\e[96mINFO: ${1-}" >&2 ; }

declare -F INFO || INFO() { LOCAL_INFO "$@" ; }
declare -F ERROR || ERROR() { LOCAL_ERROR "$@" ; }

############## Dependency checking
DEPENDENCIES_CHECK() {
    for program in "$@" ; do
        type "${program}" >/dev/null 2>&1 || {
            echo >&2 "I require ${program} but it's not installed.  Aborting."
            exit 1
        }
    done
}
DEPENDENCIES_CHECK "jq" "curl"

############## checking libraries ##############
: "${LIB_PATH:=${CICDCD_SCRIPTS_BASE_PATH}}"

############## Login
# 
# login
#     INPUTS:
#           1: URL DCOS
#           2: User_id with permission to execute CCT API
#           3: User Password
#     OUTPUTS:
#          populate COOKIE_DCOS_ACS_AUTH COOKIE_DCOS_ACS_INFO
#     EXAMPLE
#       . ./sso_login.sh &&  login_CCT <SSO_login_URL> <USER> <PASS> && echo "dcos-acs-auth-cookie=${COOKIE_DCOS_ACS_AUTH};dcos-acs-info-cookie=${COOKIE_DCOS_ACS_INFO};"
#
login_CCT() {
    local url_dcos
    local user_id
    local user_password
    local tenant
    local raw_cookies
    local response
    local status_code
    local url_login_submit
    local cookie_dcos_acs_auth
    local cookie_dcos_acs_info
    local input_lt
    local input_execution
    local curl_opts=" --connect-timeout 5 --retry 5 --retry-delay 2 --tlsv1.2 -k"
#    local curl_opts=" --connect-timeout 5 --retry 5 --retry-delay 2 --tlsv1.2 -k$( [[ "${DEBUG}" == true ]] && echo " -vvv" )"
    local old_ifs
    local cookiesFirstLogin="$(mktemp -p /dev/shm)"

    local HELP_TEXT="  Retreive SSO cookies from platform
        USAGE:
            CICDCD_SSO_URL              Envirenment variable with the url of login screen
            CICDCD_SSO_USER_ID          Envirenment variable with sso User
            CICDCD_SSO_USER_PASSWORD    Envirenment variable with sso User plataform
            CICDCD_SSO_TENANT           Envirenment variable with ID of tenant, NONE by defect
            --rawcookies                to write raw cookies to console

    "

    local options=$(getopt \
        --options h\? \
        --long rawcookies,help \
        -- "$@")

    if [[ ${#@} -ne 0 ]] && [[ ${@#"--help"} = "" ]]; then
        printf -- "%s" "${HELP_TEXT}"
        exit 0
    fi

    set -- ${options}

    local position_index_argument=0

    while [[ $# -gt 0 ]] ; do
        case $1 in
            --rawcookies)   
                raw_cookies=true
            ;;
            -h|--help|-\?)  printf -- "%s" "${HELP_TEXT}" ; exit 0 ;;
            (--)            ;;
            (-*)            printf "%s: error - unrecognized option %s" "$0" "$1" 1>&2 ; exit 1 ;;
            (*) 
                position_index_argument=$((position_index_argument+1)) 
                case ${position_index_argument} in
                    1)      url_dcos=${1:1:-1} ;;
                    2)      user_id=${1:1:-1} ;;
                    3)      user_password=${1:1:-1} ;;
                    4)      tenant=${1:1:-1} ;;
                    (*)     printf "%s: error - unrecognized option %s" "$0" "$1" 1>&2 ; exit 1 ;;
                esac
            ;;
        esac
        shift
    done

    [[ -z ${url_dcos:-} ]] && [[ -n ${CICDCD_SSO_URL} ]] && url_dcos=${url_dcos:-$CICDCD_SSO_URL}
    [[ -z ${user_id:-} ]] && [[ -n ${CICDCD_SSO_USER_ID} ]] && user_id=${user_id:-$CICDCD_SSO_USER_ID}
    [[ -z ${user_password:-} ]] && [[ -n ${CICDCD_SSO_USER_PASSWORD} ]] && user_password=${user_password:-$CICDCD_SSO_USER_PASSWORD}
    tenant=${tenant:-${CICDCD_SSO_TENANT:-NONE}}
    raw_cookies=${raw_cookies:-false}

##    declare -F INFO && INFO "url_dcos ${url_dcos} ${user_id} ${user_password} ${tenant} ${raw_cookies}"
    old_ifs=$IFS
    ############## Recuperación de los datos de conexión
    response=$( curl $curl_opts -L \
        -w "%{response_code} %{url_effective}" \
        -c "${cookiesFirstLogin}" \
        --silent \
        $url_dcos)

        IFS=' ' read input_lt input_execution <<< $( 
            echo "${response}" | 
                awk -v RS='<input ' -v FS='"' -v ORS=' ' '
                    /"execution"/ { for(i=1;i<=NF;i++) if($i ~ /value/) execution=$(i+1) }
                    /"lt"/ { for(i=1;i<=NF;i++) if($i ~ /value/) lt=$(i+1) }
                    END { print lt, execution }
                ')

    IFS=' ' read status_code url_login_submit <<< $( echo "${response}" | tail -1)

    case ${status_code} in
        2*|3*)

        ;;
        4*|5*)
            declare -F ERROR && ERROR "login - error 1 while log in DCOS http_code: ${status_code}" || 
                printf "login - error while log in DCOS http_code: %s\n" "${status_code}"
		    return 1
        ;;
        *)
            declare -F ERROR && ERROR "Invalid login endpoint ${url_dcos}. The endpoint is invalid or is unavailable." || 
                printf "Invalid login endpoint %s. The endpoint is invalid or is unavailable.\n" "${url_dcos}"
		    return 1
	esac

    ############## Login
    response=$( curl $curl_opts \
        -L \
        -w "%{response_code} %{url_effective}" \
        -b "${cookiesFirstLogin}" \
        -D - \
        --silent \
        --output /dev/null \
        --data _eventId=submit \
        --data tenant="$tenant" \
        --data username="$user_id" \
        --data password="$user_password" \
        --data lt="$input_lt" \
        --data-urlencode execution="${input_execution}" \
        --compressed --insecure \
        ${url_login_submit} )

    IFS=' ' read status_code url_login_submit <<< $( echo "${response}" | tail -1)

    INFO "[DEBUG] tenant: $tenant"
    INFO "[DEBUG] user_id: $user_id"
    INFO "[DEBUG] user_password: $user_password"
    
    case ${status_code} in
        200|201|202)
            IFS=' ' read cookie_dcos_acs_auth cookie_dcos_acs_info <<< $(
                    echo "${response}" | 
                    awk '
                        /^[sS]et-[cC]ookie:/ && /dcos-acs-auth-cookie=/ { auth=$2; next}
                        /^[sS]et-[cC]ookie:/ && /dcos-acs-info-cookie=/ { info=$2; next}
                        END{print auth, info} 
                    ')
        ;;
        4*|5*)
            declare -F ERROR && ERROR "login - error 1 while log in SSO http_code: ${status_code}" || 
                printf "login - error 1 while log in SSO http_code: %s\n" "${status_code}"
            IFS=$old_ifs
		    return 1
        ;;
        *)
            declare -F ERROR && ERROR "Invalid login endpoint. The endpoint is invalid or is unavailable." || 
                printf "Invalid login endpoint. The endpoint is invalid or is unavailable. \n"
            IFS=$old_ifs
		    return 1
	esac

    if [[ -z $cookie_dcos_acs_auth ]] || [[ -z $cookie_dcos_acs_info ]] ; then
        declare -F ERROR && ERROR "Login failed for user ${user_id}. Verify passwaord." || 
            printf "Login failed for user %s. Verify password.\n" "${user_id}"
        IFS=$old_ifs
        return 1
    fi

    if [[ "${raw_cookies}" == true ]] ; then
        echo "${cookie_dcos_acs_auth}${cookie_dcos_acs_info}"
    fi

    cookie_dcos_acs_auth="${cookie_dcos_acs_auth##dcos-acs-auth-cookie=}"
    cookie_dcos_acs_info="${cookie_dcos_acs_info##dcos-acs-info-cookie=}"

    export COOKIE_DCOS_ACS_AUTH="${cookie_dcos_acs_auth%?}"
    export COOKIE_DCOS_ACS_INFO="${cookie_dcos_acs_info%?}"

    IFS="${old_ifs}"
    rm "${cookiesFirstLogin}" 2> /dev/null

    return 0
}

#################################
# Internal function to sanitize the service ID, compatible with tenant management.
# Function to get real service ID into Pegaso platform using tenants
#
#   For example, a service hello-world deployed into Tenant cicd would be:
#    cicd/cicd-hello-world  --> generic format : {TENANT}/{TENANT}-{SERVICE_NAME}
#
# Parameters:
#    param 1: Application name
#    param 2: tenant id
#
__sanitizedServiceID() {
    local appName=${1:-}
    local tenantId=${2:-}
    local serviceName=""

    local serviceId="${appName##*/}"
    local groupId="${appName/%${serviceId}/}"

    if [[ "${tenantId}" == "NONE" ]] ; then 
        tenantId=""
    fi

    tenantId="${tenantId,,}"
    [[ -n "${tenantId}" ]] && serviceName="${tenantId}/${groupId}/${tenantId}-${serviceId}" || serviceName="${appName}"

    echo "${serviceName}" | tr -s '/'
}

#################################
# Helper function to identify $CCT_API_VERSION: OLD, OLDER o NEW. Default value is NEW.
__getAPIVersion() {

    local cct_base_url="${CCT_URL:-}"
    local cookies="${AUTH_COOKIE}"

    local cctApiVersion=""
    local endpointUrl=""

    local curl_opts=""
    curl_opts="${curl_opts} --connect-timeout 2 --retry 2 --retry-delay 2 --tlsv1.2"
    curl_opts="${curl_opts} --silent --insecure"

    endpointUrl="$(CCT_URL="${cct_base_url}" CCT_API_VERSION="NEW" APPLICATION="undefined" __getAPIEndpoint "APPLICATION_LOGS")"

    httpResponse=$(curl $curl_opts --write-out "\n%{http_code}" --cookie "${cookies}" -H "Accept:application/json" "${endpointUrl}")

    status_code=$(echo "${httpResponse}" | tail -1)

    case ${status_code} in
        000) ERROR "Unable to identify CCT_API_VERSION: fail to connect to ${endpointUrl}." ; return 1 ;;
        404) cctApiVersion="NEW" ;;
        401) ERROR "Unable to identify CCT_API_VERSION: unauthorized to connect to ${endpointUrl}." ; return 1 ;;
        *) ;;
    esac

    if [[ -z "${cctApiVersion}" ]] ; then
        endpointUrl="$(CCT_URL="${cct_base_url}" CCT_API_VERSION="OLD" APPLICATION="undefined" __getAPIEndpoint "APPLICATION_LOGS")"
        httpResponse=$(curl $curl_opts --write-out "\n%{http_code}" --cookie "${cookies}" -H "Accept:application/json" "${endpointUrl}")
        status_code=$(echo "${httpResponse}" | tail -1)

        case ${status_code} in
            000) ERROR "Unable to identify CCT_API_VERSION: fail to connect to ${endpointUrl}." ; exit 1 ;;
            400) cctApiVersion="OLD" ;;
            401) ERROR "Unable to identify CCT_API_VERSION: unauthorized to connect to ${endpointUrl}." ; exit 1 ;;
            404) cctApiVersion="OLDER" ;;
            *)  ;;
        esac
    fi

    echo "${cctApiVersion}"
}

#################################
# Identication of CCT API URL based on $CCT_VERSION: OLD, OLDER o NEW. Default value is NEW.
__getAPIEndpoint() {

    local label="$1"
    local publishTenant="${CCT_TENANT}"
    local application="${APPLICATION:-}"
    local cctService="${CCT_SERVICE}"
    local cctModel="${CCT_MODEL}"
    local cctVersion="${CCT_VERSION}"
    local cct_base_url="${CCT_URL:-$CICDCD_SSO_URL}"
    local cctApiVersion="${CCT_API_VERSION:-NEW}"

    case "${cctApiVersion}" in
        "OLDER") 
            case "${label}" in
                "CCT_GLOBALS") echo "${cct_base_url}/service/deploy-api/central/globals" ;;
                "APPLICATION_DEPLOYMENT_DESCRIPTOR") echo "${cct_base_url}/service/deploy-api/deploy/${cctService}/${cctModel}/schema" ;;
                "APPLICATION_SERVICE_DESCRIPTOR") echo "${cct_base_url}/service/deploy-api/universe/${cctService}/${cctModel}/descriptor" ;;
                "APPLICATION_SERVICE_DESCRIPTOR_VERSION") echo "${cct_base_url}/service/deploy-api/universe/${cctService}/${cctModel}/versions" ;;
                "APPLICATION_STATUS") echo "${cct_base_url}/service/deploy-api/deployments/service?instanceName=/${application}" ;;
                "APPLICATION_UPDATE") echo "${cct_base_url}/service/deploy-api/update/${application}" ;;
                "APPLICATION_UPGRADE") echo "${cct_base_url}/service/deploy-api/upgrade/${cctService}/${cctModel}/${application}" ;;
                "APPLICATION_UNINSTALL") echo "${cct_base_url}/service/deploy-api/deploy/uninstall?app=/${application}&force=true" ;;
                "APPLICATION_LOGS") echo "${cct_base_url}/service/deploy-api/deployments/logs/${application}" ;;
                *) echo "";
            esac
        ;;
        "OLD")
            case "${label}" in
                "CCT_GLOBALS") echo "${cct_base_url}/service/deploy-api/central/globals" ;;
                "APPLICATION_DEPLOYMENT_DESCRIPTOR") echo "${cct_base_url}/service/deploy-api/deploy/${cctService}/${cctModel}/${cctVersion}/schema" ;;
                "APPLICATION_SERVICE_DESCRIPTOR") echo "${cct_base_url}/service/deploy-api/universe/${cctService}/${cctModel}/${cctVersion}/descriptor" ;;
                "APPLICATION_SERVICE_DESCRIPTOR_VERSION") echo "${cct_base_url}/service/deploy-api/universe/${cctService}/${cctModel}/versions" ;;
                "APPLICATION_STATUS") echo "${cct_base_url}/service/deploy-api/deployments/service?instanceName=/${application}" ;;
                "APPLICATION_UPDATE") echo "${cct_base_url}/service/deploy-api/update/${application}" ;;
                "APPLICATION_UPGRADE") echo "${cct_base_url}/service/deploy-api/upgrade/${cctService}/${cctModel}/${cctVersion}/${application}" ;;
                "APPLICATION_UNINSTALL") echo "${cct_base_url}/service/deploy-api/deploy/uninstall?app=/${application}&force=true" ;;
                "APPLICATION_LOGS") echo "${cct_base_url}/service/deploy-api/deployments/logs/${application}" ;;
                *) echo "";
            esac
        ;;
        "NEW")
            case "${label}" in
                "CCT_GLOBALS") echo "${cct_base_url}/service/cct-deploy-api/central/globals" ;;
                "APPLICATION_DEPLOYMENT_DESCRIPTOR") echo "${cct_base_url}/service/cct-deploy-api/deploy/${cctService}/${cctModel}/${cctVersion}/schema" ;;
                "APPLICATION_SERVICE_DESCRIPTOR") echo "${cct_base_url}/service/cct-universe/v1/descriptors/${cctService}/${cctModel}/${cctVersion}" ;;
                "APPLICATION_SERVICE_DESCRIPTOR_VERSION") echo "${cct_base_url}/service/cct-deploy-api/universe/${cctService}/${cctModel}/versions" ;;
                "APPLICATION_STATUS") echo "${cct_base_url}/service/cct-marathon-services/v1/services/${application}" ;;
                "APPLICATION_UPDATE") echo "${cct_base_url}/service/cct-deploy-api/update/${application}" ;;
                "APPLICATION_UPGRADE") echo "${cct_base_url}/service/cct-deploy-api/upgrade/${cctService}/${cctModel}/${cctVersion}/${application}" ;;
                "APPLICATION_UNINSTALL") echo "${cct_base_url}/service/cct-deploy-api/deploy/uninstall?app=/${application}&force=true" ;;
                "APPLICATION_LOGS") echo "${cct_base_url}/service/cct-marathon-services/v1/services/tasks/${application}/logs" ;;
                *) echo "";
            esac
        ;;
        *) ;;
    esac
}

#################################
# Internal function to update serviceID parameter inside deploye file.
__updateDeployerServiceID() {
    local descriptorFilePath=${1:-}
    local tenantId=${2:-}
    local tempDeployedJson=$(mktemp)

    serviceId=$(jq -r '.general.serviceId' "${descriptorFilePath}")
    serviceId=$(__sanitizedServiceID "${serviceId}" "${tenantId}")
#	INFO "Sanitized serviceId: ${serviceId}"
    
    jq -c '.general.serviceId = $newVal' --arg newVal "${serviceId}" "${descriptorFilePath}" > "${tempDeployedJson}"

    echo "${tempDeployedJson}"
}

#################################
# Internal function to invoke CCT API with curl.
#
# Parameters:
#    param 1: Method to use (GET, PUT, POST, DELETE)
#    param 2: endpoint url
#    param 3: json body
#
__invoqueService() {
    local action=${1:-}
    local endpointUrl=${2:-}
    local jsonParameterFile=${3:-}

    local cookies="${CICDCD_AUTH_COOKIES}"

    local curl_opts=" --connect-timeout 5 --retry 5 --retry-delay 2 --tlsv1.2"

#	INFO "Calling this endpoint: ${endpointUrl}"
#	INFO "Calling this endpoint: ${endpointUrl} with cookie ${cookies}"

#	curl_opts="${curl_opts} -vvv --insecure"
    curl_opts="${curl_opts} --silent --insecure"
    case "${action}" in
        GET)
            httpResponse=$(curl $curl_opts                            \
                            --write-out "\n%{http_code}" \
                            --cookie "${cookies}"                 \
                            -X GET                                \
                            -H "Accept:application/json"          \
                            "${endpointUrl}")
        ;;
        POST)
            httpResponse=$(curl $curl_opts                            \
                            --write-out "\n%{http_code}" \
                            --cookie "${cookies}"                 \
                            -X POST                                \
                            -H "Accept:application/json"          \
                            -H "Content-Type:application/json"    \
                            -d @$jsonParameterFile               \
                            "${endpointUrl}")
        ;;
        PUT)
            httpResponse=$(curl $curl_opts                            \
                            --write-out "\n%{http_code}" \
                            --cookie "${cookies}"                 \
                            -X PUT                                \
                            -H "Accept:application/json"          \
                            -H "Content-Type:application/json"    \
                            -d @$jsonParameterFile               \
                            "${endpointUrl}")
        ;;
        DELETE)
            httpResponse=$(curl $curl_opts                            \
                            --write-out "\n%{http_code}" \
                            --cookie "${cookies}"                 \
                            -X DELETE                                \
                            -H "Accept:*/*"          \
                            "${endpointUrl}")
        ;;
        *)
            ERROR "Unknown action"
            return 1
    esac

    data=$(echo "${httpResponse}" | head -1 )
    status_code=$(echo "${httpResponse}" | tail -1)

#	INFO "status ${status_code} data: ${data}"

    echo "${data}"
    
    INFO "AQUI URL: ${endpointUrl}"
    INFO "AQUI STATUS CODE: ${status_code}"

    case ${status_code} in
        000)
            ERROR "Fail to connect to ${endpointUrl} (return ${data})."
            exit 1
        ;;
        200|201|202)
#			INFO "Endpoint invoked successfully: ${data}"
            echo "${httpResponse}"
        ;;
        400)
            INFO "service locked: ${status_code} data: ${data}"
            return 1
        ;;
        403)
            INFO "Authentication failed: ${status_code} data: ${data}"
            return 1
        ;;
        4*|5*)
            INFO "Endpoint ${endpointUrl} with action "${action}" NOT invoked successfully: ${status_code} data: ${data}"
            return 1
        ;;
        *)
            INFO "Endpoint ${endpointUrl} with action "${action}" NOT invoked successfully: ${status_code} data: ${data}"
            return 1
    esac

}

#################################
# Internal function that log into CCT if necesary and retrieve the auth cookie in the format 
# expected by the process: 
#     
#    dcos-acs-auth-cookie=XXXXXXXX;dcos-acs-info-cookie=XXXXXXXXX;
#
# and save the content in AUTH_COOKIE variable.
# Parameters:
#    param 1: cct base url
#
#    if cookie is provided:
#    param 2: auth cookie
#
#    if user and password are provided:
#    param 2: user id
#    param 3: user password
#
#    if user, password and OSS tenant are provided:
#    param 2: user id
#    param 3: user password
#    param 4: user tenant
#
#	In all other case, it's trying to recover password from shell variable COOKIE_DCOS_ACS_AUTH and COOKIE_DCOS_ACS_AUTH
#
__retrieveCookie() {
    local login_url="$1"
    local cookies

#	INFO "Invoking __retrieveCookie"

    case "$#" in
        4)
            cookies=$(CICDCD_SSO_USER_ID="${2}" CICDCD_SSO_USER_PASSWORD="${3}" CICDCD_SSO_URL="${login_url}/login" CICDCD_SSO_TENANT="${4}" login_CCT --rawcookies)
        ;;
        3)
            cookies=$(CICDCD_SSO_USER_ID="${2}" CICDCD_SSO_USER_PASSWORD="${3}" CICDCD_SSO_URL="${login_url}/login" login_CCT --rawcookies)
        ;;
        2)
            cookies="$2"
        ;;
        *)
            cookies=""
            if  [[ -z "${AUTH_COOKIE:-}" ]] && [[ -n "${COOKIE_DCOS_ACS_AUTH:-}" ]] && [[ -n "${COOKIE_DCOS_ACS_INFO:-}" ]] ; then
#				INFO "Auth cookie and info cookie has been provided in the call"
                cookies="dcos-acs-auth-cookie=${COOKIE_DCOS_ACS_AUTH};dcos-acs-info-cookie=${COOKIE_DCOS_ACS_INFO};"
            else
                cookies=${AUTH_COOKIE:-}
            fi
    esac
#	INFO "Getting cookies: ${cookies}"

    echo "${cookies}"
}

#################################
# Internal function to retrieve status of deployed service, taking into account the tenant reference if exists
#
# Parameters:
#		CICDCD_SSO_URL              Envirenment variable with the url of login screen
#		CICDCD_SERVICE_TENANT       Envirenment variable with tenant name, if exist
#		AUTH_COOKIE           		Envirenment variable with atuhentication cookies, opcional
#   	param 1 					application name, with its groupId if necesaary. I.e. hello/hello-world
#
_getStatus() {
    local application=$1
    local mandatoryArguments=1

    local cct_base_url="${CICDCD_SSO_URL:-}"
    local userSsoTenant="${CICDCD_SSO_TENANT:-}"
    local serviceTenant="${CICDCD_SERVICE_TENANT:-}"

    local httpResponse=""
    local data=""
    local status_code=""
    local cookies=""

    local returnCode=1
    
    application=$(__sanitizedServiceID "${application}" "${serviceTenant}")

    local deployEndpointUrl=""
#    deployEndpointUrl="${cct_base_url}/service/deploy-api/deployments/service?instanceName=/${application}"
    deployEndpointUrl="$(APPLICATION=${application} __getAPIEndpoint "APPLICATION_STATUS")"

    if [[ -n ${AUTH_COOKIE:-} ]] ; then
        cookies="${AUTH_COOKIE}"
    else
        if [[ "$#" -ge "${mandatoryArguments}" ]] ; then
            shift "${mandatoryArguments}"	
            cookies=$(CICDCD_SSO_TENANT="${userSsoTenant}" __retrieveCookie "${cct_base_url}" "$@")
        fi
    fi

    INFO "Getting application ${application} status in CCT (${deployEndpointUrl}) "

    httpResponse=$(CICDCD_AUTH_COOKIES="${cookies}" __invoqueService "GET" "${deployEndpointUrl}") && returnCode=0 || returnCode=1

#	INFO "Return code: ${returnCode}"

    data=$(echo "${httpResponse}" | head -1 )
    echo "${data}"

    return $returnCode
}

#################################
# Checks if an application is present in cct.
# The published tenant is retrived from the shell variable CICDCD_SERVICE_TENANT.
#
# If 3 params are given, then the
# last one is spected to be the auth cookie in the format expected. If 4 params
# are given, then user and password are used to retrieve the auth cookie by
# invoking login_CCT func.
#
# Parameters:
#	 CICDCD_SSO_TENANT           Envirenment variable with tenant of the tenant user
#	 CICDCD_SERVICE_TENANT       Envirenment variable with tenant name, if exist
#
#    param 1: cct base url. I.e. https://eos.client.domainname.com
#    param 2: application name, with groupId if exist. I.e. /hello/hello-world
#
#    if cookie provided:
#    param 3: auth cookie
#
#    if user and password provided:
#    param 3: user identification
#    param 4: password
#
#    if user, password and OSS tenant are provided:
#    param 3: user id
#    param 4: user password
#    param 5: user tenant
#
isDeployed() {
    local cct_base_url=$1
    local application=$2
    local userSsoTenant="${CICDCD_SSO_TENANT:-}"
    local serviceTenant="${CICDCD_SERVICE_TENANT:-}"

    local cctTimeout="${CICDCD_CCT_TIMEOUT:-0}"
    local isTimeOut=false
    local isDeployed=false
    local dateMax=""

    local data=""

    shift

    if [[ cctTimeout -gt 0 ]] ; then
        dateMax=$(( $(date +%s) + cctTimeout ))
        INFO "isDeployed invocation will be retry during ${cctTimeout} seconds, until $(date -d @${dateMax})."
    fi

    while
        data=$(
                CICDCD_SSO_URL="${cct_base_url}" \
                CICDCD_SERVICE_TENANT="${serviceTenant}" \
                CICDCD_SSO_TENANT="${userSsoTenant}" \
                _getStatus "$@"
            ) && isDeployed=true || isDeployed=false

        [[ "${dateMax}" -lt $(date +%s) ]] && isTimeOut=true || isTimeOut=false
        [[ "${isTimeOut}" == false && "${isDeployed}" == false ]]
    do
        sleep 5
    done

    if [[ -n "${dateMax}" && "${isTimeOut}" == true ]] ; then
        ERROR "Checking if ${application} exists failed."
        returnCode=1
    elif [[ "${isDeployed}" == true ]] ; then
        INFO "Application ${application} exists."
        returnCode=0
    else
        INFO "Application ${application} doesn't exist."
        returnCode=1
    fi

    return "${returnCode}"
}

#################################
# Checks if an application is healthy in cct by checking the .healthy and
# .status attributes. If 3 params are given, then the last one is spected
# to be the auth cookie in the format expected. If 4 params are given,
# then user and password are used to retrieve the auth cookie by invoking
# login_CCT func.
#
# Parameters:
#	 CICDCD_SSO_TENANT           Envirenment variable with tenant of the tenant user
#	 CICDCD_SERVICE_TENANT       Envirenment variable with tenant name, if exist
#
#    param 1: cct base url. I.e. https://eos.client.domainname.com
#    param 2: application name. I.e. hello-world
#
#    if cookie provided:
#    param 3: auth cookie
#
#    if user and password provided:
#    param 3: user identification
#    param 4: password

function healthCheckApp {
    local cct_base_url=$1
    local application=$2
    local userSsoTenant="${CICDCD_SSO_TENANT:-}"
    local serviceTenant="${CICDCD_SERVICE_TENANT:-}"

    local cctTimeout="${CICDCD_CCT_TIMEOUT:-0}"
    local isTimeOut=false
    local isDeployed=false
    local isHealthy=false
    local dateMax=""

    local data=""
    local healthy=""
    local status=""

    shift

    if [[ cctTimeout -gt 0 ]] ; then
        dateMax=$(( $(date +%s) + cctTimeout ))
        INFO "healthCheckApp invocation will be retry during ${cctTimeout} seconds, until $(date -d @${dateMax})."
    fi

    while
        data=$(
                CICDCD_SSO_URL="${cct_base_url}" \
                CICDCD_SERVICE_TENANT="${serviceTenant}" \
                CICDCD_SSO_TENANT="${userSsoTenant}" \
                _getStatus "$@"
            ) && isDeployed=true || isDeployed=false

        if [[ "${isDeployed}" == true ]] ; then

#            healthy=$(echo "${data}" | jq -r '.healthy')
#            status=$(echo "${data}" | jq -r '.status')
#
#            [[ "${healthy}" -eq 1 && "${status}" -eq 2 ]] && isHealthy=true || isHealthy=false

            healthy=$(echo "${data}" | jq -r -e '
                . | select ( .status | tostring | test( "2|RUNNING") )
                        and ( has("healthiness") and select( .healthiness | test("HEALTHY"))
                                or (has("healthy") and select( .healthy == 1)))
                ') && isHealthy=true || isHealthy=false
        fi

        [[ "${dateMax}" -lt $(date +%s) ]] && isTimeOut=true || isTimeOut=false
        [[ "${isTimeOut}" == false && "${isHealthy}" == false ]]
    do
        sleep 5
    done

    if [[ -n "${dateMax}" && "${isTimeOut}" == true &&  "${isDeployed}" == false ]] ; then
        ERROR "Checking aplication ${application} health failed."
        returnCode=1
    elif [[ "${isHealthy}" == true ]] ; then
        INFO "App: ${application} is healthy."
        returnCode=0
    else
        INFO "App: ${application} is not healthy."
        returnCode=102
    fi

    return "${returnCode}"
}

#################################
# Given an application, get the deployement json from CCT by invoking the deployment api.
#
# Parameters:
#		CICDCD_SSO_URL              Envirenment variable with the url of login screen
#		CICDCD_SERVICE_TENANT       Envirenment variable with tenant name, if exist
#		AUTH_COOKIE           		Envirenment variable with atuhentication cookies, mandatory
#   	param 1 					application name, with its groupId if necesaary. I.e. hello/hello-world
#
function _getApplicationDeployementJSON {
    local application=$1

    local cct_base_url="${CICDCD_SSO_URL:-}"
    local publishTenant="${CICDCD_SERVICE_TENANT:-}"
    local cookies="${AUTH_COOKIE:-}"

    local httpResponse=""
    local data=""

    local deployEndpointUrl=""
    local returnCode=""

    application=$(__sanitizedServiceID "${application}" "${publishTenant}")

#    deployEndpointUrl="${cct_base_url}/service/deploy-api/update/${application}"
    deployEndpointUrl="$(APPLICATION=${application} __getAPIEndpoint "APPLICATION_UPDATE")"

    INFO "Get application deployement json from CCT (${deployEndpointUrl})"

    httpResponse=$(CICDCD_AUTH_COOKIES="${cookies}" __invoqueService "GET" "${deployEndpointUrl}" ) && returnCode=0 || returnCode=1

    if [[ "${returnCode}" == 0 ]] ; then
        INFO "Service descriptor: ${cctService} installed"
        data=$(echo "${httpResponse}" | head -1 )
    else
        ERROR "Service descriptor: ${cctService} is not installed"
    fi
    echo "${data:-}"
    return "${returnCode}"
}

#################################
# Update a given application into CCT by invoking the deployment api and
# using a deployment descriptor. To do that an auth cookie can be privided in
# parameter number 4. Also can be provided user and password in params 4 and 5.
#
# Parameters:
#		CICDCD_SSO_URL              Envirenment variable with the url of login screen
#		CICDCD_SERVICE_TENANT       Envirenment variable with tenant name, if exist
#		AUTH_COOKIE           		Envirenment variable with atuhentication cookies, mandatory
#
#    param 1: application name, with its groupId if necesaary. I.e. hello/hello-world
#    param 2: deployment descriptor file path
#
function _updateApplication {
    local application=$1
    local descriptorFilePath=$2

    local cct_base_url="${CICDCD_SSO_URL:-}"
    local serviceTenant="${CICDCD_SERVICE_TENANT:-}"
    local cookies="${AUTH_COOKIE:-}"

    local httpResponse=""
    local data=""
    local status_code=""

    local deployEndpointUrl=""

    tempDeployedJson=$(__updateDeployerServiceID "${descriptorFilePath}" "${serviceTenant}")
    application=$(jq -r '.general.serviceId' "${tempDeployedJson}")

#    deployEndpointUrl="${cct_base_url}/service/deploy-api/update/${application}"
    deployEndpointUrl="$(APPLICATION=${application} __getAPIEndpoint "APPLICATION_UPDATE")"

    INFO "Updating application ${application} in CCT (${deployEndpointUrl}) \
    using this deployment descriptor: ${descriptorFilePath}"

    httpResponse=$(CICDCD_AUTH_COOKIES="${cookies}" __invoqueService "PUT" "${deployEndpointUrl}" "${tempDeployedJson}") && returnCode=0 || returnCode=1

    if [[ "${returnCode}" == 0 ]] ; then
        INFO "App: ${application} updated"
    else
        ERROR "App: ${application}, not updated"
    fi

    return "${returnCode}"
}

#################################
# Internal function to update a deployed service, compatible with Pegaso EOS version.
#
# Parameters:
#		CICDCD_SSO_URL              Envirenment variable with the url of login screen
#		CICDCD_SERVICE_TENANT       Envirenment variable with tenant name, if exist
#		AUTH_COOKIE           		Envirenment variable with atuhentication cookies, mandatory
#
#    param 1: cct service
#    param 2: cct model
#    param 3: cct application name
#    param 4: deployment descriptor file path
#    param 5: version
#
function _upgradeApplication {
    local cctService=$1
    local cctModel=$2
    local serviceName=$3
    local deploymentDescriptor=$4
    local cctVersion="${5:-}"

    local cct_base_url="${CICDCD_SSO_URL:-}"
    local publishTenant="${CICDCD_SERVICE_TENANT:-}"
    local cookies="${AUTH_COOKIE:-}"

    local application=""
    local mandatoryArguments=5

    local httpResponse=""
    local tempDeployedJson=$(mktemp)

    local deployEndpointUrl=""

    application=$(__sanitizedServiceID "${serviceName}" "${publishTenant}")
    jq -c '.general.serviceId = $newVal' --arg newVal "${application}" "${deploymentDescriptor}" > "${tempDeployedJson}"
    application=$(jq -r '.general.serviceId' "${tempDeployedJson}")
#	INFO "cat $tempDeployedJson"

#    if [[ -n "${cctVersion}" ]] ; then
#        deployEndpointUrl="${cct_base_url}/service/deploy-api/upgrade/${cctService}/${cctModel}/${cctVersion}/${application}"
#    else
#        deployEndpointUrl="${cct_base_url}/service/deploy-api/upgrade/${cctService}/${cctModel}/${application}"
#    fi
    deployEndpointUrl="$(
        CCT_SERVICE=${cctService} \
        CCT_MODEL=${cctModel} \
        CCT_VERSION=${cctVersion} \
        APPLICATION=${application} \
            __getAPIEndpoint "APPLICATION_UPGRADE")"

    INFO "Installing application ${application} in CCT (${deployEndpointUrl}) \
    using this deployment descriptor: ${deploymentDescriptor}"

#	INFO "Calling this endpoint: ${deployEndpointUrl} with cookie ${cookies}"
    httpResponse=$(
            CICDCD_AUTH_COOKIES="${cookies}" __invoqueService "PUT" "${deployEndpointUrl}" "${tempDeployedJson}"
        ) && returnCode=0 || returnCode=1

    if [[ "${returnCode}" == 0 ]] ; then
        INFO "App: ${application} upgraded"
    else
        ERROR "App: ${application}, not upgraded"
    fi

    return "${returnCode}"
}

#################################
# Internal function
#
# Install a given application into CCT by invoking the deployment api and
# using a deployment descriptor. It also need the service name template and
# its corresponding model as params.
#
# The service name is extected from the deployment descriptor.
# The reference to the tenant where to publish the service must be specified in
# the shell variable CICDCD_SERVICE_TENANT.
#
# Parameters:
#		CICDCD_SSO_URL              Envirenment variable with the url of login screen
#		CICDCD_SERVICE_TENANT       Envirenment variable with tenant name, if exist
#		AUTH_COOKIE           		Envirenment variable with atuhentication cookies, mandatory
#		CICDCD_CCT_TIMEOUT     		Timeout to retreive info, opcional
#
#    param 1: cct service
#    param 2: cct model
#    param 3: deployment descriptor file path
#    param 4: version
#
function _installApplication {
    local cctService=$1
    local cctModel=$2
    local deploymentDescriptor=$3
    local cctVersion="${4:-}"
    local mandatoryArguments=3

    local cct_base_url="${CICDCD_SSO_URL:-}"
    local publishTenant="${CICDCD_SERVICE_TENANT:-}"
    local cookies="${AUTH_COOKIE:-}"

    local cctTimeout="${CICDCD_CCT_TIMEOUT:-0}"
    local isTimeOut=false
    local isPublished=false
    local isNotSynchronizedETCD=false
    local isLocked=false
    local dateMax=""

    local httpResponse=""
    local data=""
    local status_code=""
    local serviceId=""
    local tempDeployedJson=""

    local deployEndpointUrl=""
    local globalEndpointUrl=""

#    if [[ -n "${cctVersion}" ]] ; then
#        deployEndpointUrl="${cct_base_url}/service/deploy-api/deploy/${cctService}/${cctModel}/${cctVersion}/schema"
#    else
#        deployEndpointUrl="${cct_base_url}/service/deploy-api/deploy/${cctService}/${cctModel}/schema"
#    fi
    deployEndpointUrl="$(
        CCT_SERVICE=${cctService} \
        CCT_MODEL=${cctModel} \
        CCT_VERSION=${cctVersion} \
            __getAPIEndpoint "APPLICATION_DEPLOYMENT_DESCRIPTOR")"

    if [[ -n "${publishTenant}" ]] && [[ "${publishTenant}" != "NONE" ]] ; then
        deployEndpointUrl="${deployEndpointUrl}?tenantId=${publishTenant}"
    fi

    INFO "Calling this endpoint: ${deployEndpointUrl}"

    tempDeployedJson=$(__updateDeployerServiceID "${deploymentDescriptor}" "${publishTenant}")
    application=$(jq -r '.general.serviceId' "${tempDeployedJson}")

    INFO "Installing application in CCT (${deployEndpointUrl}) \
    using this deployment descriptor: ${deploymentDescriptor}"

    tempDeployedJson=$(__updateDeployerServiceID "${deploymentDescriptor}" "${publishTenant}")
    application=$(jq -r '.general.serviceId' "${tempDeployedJson}")

#	INFO "cat ${tempDeployedJson}"

#	INFO "Calling this endpoint: ${deployEndpointUrl}"

    if [[ cctTimeout -gt 0 ]] ; then
        dateMax=$(( $(date +%s) + cctTimeout ))
        INFO "install application will be retry during ${cctTimeout} seconds, until $(date -d @${dateMax})."
    fi

    while
        httpResponse=$(
                CICDCD_AUTH_COOKIES="${cookies}" __invoqueService "POST" "${deployEndpointUrl}" "${tempDeployedJson}"
            ) && isPublished=true || isPublished=false

#		INFO "response ${httpResponse}"
        $(echo "${httpResponse}" | grep -oq "cannot interpolate") && isNotSynchronizedETCD=true || isNotSynchronizedETCD=false
        if [[ "${isNotSynchronizedETCD}" == true ]] ; then
            INFO "Interpolation problem with ETCD. Forcing ETCD synchronisation."
            globalEndpointUrl="$(__getAPIEndpoint "CCT_GLOBALS")"
            httpResponseETCD=$(
                CICDCD_AUTH_COOKIES="${cookies}" __invoqueService "GET" "${globalEndpointUrl}"
                ) && isNotSynchronizedETCD=true || isNotSynchronizedETCD=false
        fi

        [[ "${dateMax}" -lt $(date +%s) ]] && isTimeOut=true || isTimeOut=false
        $(echo "${httpResponse}" | grep -oq "App is locked by one or more deployments") && isLocked=true || isLocked=false
        [[ "${isTimeOut}" == false && ( "${isPublished}" == false || "${isLocked}" == true ) ]]
    do
        sleep 5
    done

    if [[ -n "${dateMax}" && "${isTimeOut}" == true ]] ; then
        ERROR "Application deployement for ${application} failed due to timeout"
        returnCode=1
    elif [[ ( "${isPublished}" == false || "${isLocked}" == true ) ]] ; then
        ERROR "Application deployement for ${application} failed"
        returnCode=1
    else
        INFO "Application deployment for ${application} successfully performed"
        returnCode=0
    fi

    return "${returnCode}"
}

#################################
# Internal functional
#
# Install a given service descriptor service into CCT by invoking the universe api and
# using a descriptor.
#
# Parameters:
#		CICDCD_SSO_URL              Envirenment variable with the url of login screen
#		AUTH_COOKIE           		Envirenment variable with atuhentication cookies, mandatory
#		CICDCD_CCT_TIMEOUT     		Timeout to retreive info, opcional
#
#    param 2: template service in cct, i.e. microservice
#    param 3: templante service model in cct, i.e. cicdcd
#    param 4: service descriptor file path
#    param 5: version, opcional
#
function _installServiceDescriptor {
    local cctService=$1
    local cctModel=$2
    local serviceDescriptor=$3
    local cctVersion="${4:-}"

    local cct_base_url="${CICDCD_SSO_URL:-}"
    local cookies="${AUTH_COOKIE:-}"

    local cctTimeout="${CICDCD_CCT_TIMEOUT:-0}"
    local isTimeOut=false
    local isPublished=false
    local isLocked=false
    local dateMax=""

    local httpResponse=""
    local data=""
    local status_code=""
    local serviceId=""
    local tempDescriptorJson=""

    local deployEndpointUrl=""

#    if [[ -n "${cctVersion}" ]] ; then
#        deployEndpointUrl="${cct_base_url}/service/deploy-api/universe/${cctService}/${cctModel}/${cctVersion}/descriptor"
#    else
#        deployEndpointUrl="${cct_base_url}/service/deploy-api/universe/${cctService}/${cctModel}/descriptor"
#    fi
    deployEndpointUrl="$(
        CCT_SERVICE=${cctService} \
        CCT_MODEL=${cctModel} \
        CCT_VERSION=${cctVersion} \
            __getAPIEndpoint "APPLICATION_SERVICE_DESCRIPTOR")"

    INFO "Installing service descriptor in CCT (${deployEndpointUrl}) \
    using this service descriptor: ${serviceDescriptor}"

    tempDescriptorJson="${serviceDescriptor}"

#	INFO "cat ${tempDescriptorJson}"

#	INFO "Calling this endpoint: ${deployEndpointUrl}"

    if [[ cctTimeout -gt 0 ]] ; then
        dateMax=$(( $(date +%s) + cctTimeout ))
    fi

    while
        httpResponse=$(CICDCD_AUTH_COOKIES="${cookies}" __invoqueService "POST" "${deployEndpointUrl}" "${tempDescriptorJson}") && isPublished=true || isPublished=true
        [[ "${dateMax}" -lt $(date +%s) ]] && isTimeOut=true || isTimeOut=false

        isLocked=$(echo "${httpResponse}" | grep -oq "App is locked by one or more deployments") && echo true || echo false
        [[ "${isTimeOut}" == false && ( "${isPublished}" == false || "${isLocked}" == true ) ]]
    do
        sleep 5
    done

    if [[ -n "${dateMax}" && "${isTimeOut}" == true ]] ; then
        ERROR "Service descriptor deployment for ${cctService}/${cctModel}/${cctVersion} failed due to timeout"
        returnCode=1
    elif [[ ( "${isPublished}" == false || "${isLocked}" == true ) ]] ; then
        ERROR "Service descriptor deployment for ${cctService}/${cctModel}/${cctVersion} failed"
        returnCode=1
    else
        INFO "Service descriptor deployment for ${cctService}/${cctModel}/${cctVersion} successfully performed"
        returnCode=0
    fi

    return "${returnCode}"
}

#################################
# Internal functional
#
# Get a given descriptor service into CCT by invoking the universe api
#
# Parameters:
#		CICDCD_SSO_URL              Envirenment variable with the url of login screen
#		AUTH_COOKIE           		Envirenment variable with atuhentication cookies, mandatory
#
#    param 1: template service in cct, i.e. microservice
#    param 2: templante service model in cct, i.e. cicdcd
#    param 3: version, opcional
#
function _getServiceDescriptor {
    local cctService=$1
    local cctModel=$2
    local cctVersion="${3:-}"

    local cct_base_url="${CICDCD_SSO_URL:-}"
    local cookies="${AUTH_COOKIE:-}"
    local cctTimeout="${CICDCD_CCT_TIMEOUT:-0}"
    local dateMax=""

    local httpResponse=""
    local data=""
    local status_code=""
    local serviceId=""
    local tempDescriptorJson=""

    local deployEndpointUrl=""

    if [[ -z "${cct_base_url}" ]] ; then
        ERROR "CCT URL is missing"
        return 1
    fi

#    if [[ -n "${cctVersion}" ]] ; then
#        deployEndpointUrl="${cct_base_url}/service/deploy-api/universe/${cctService}/${cctModel}/${cctVersion}/descriptor"
#    else
#        deployEndpointUrl="${cct_base_url}/service/deploy-api/universe/${cctService}/${cctModel}/descriptor"
#    fi
    deployEndpointUrl="$(
        CCT_SERVICE=${cctService} \
        CCT_MODEL=${cctModel} \
        CCT_VERSION=${cctVersion} \
            __getAPIEndpoint "APPLICATION_SERVICE_DESCRIPTOR")"

    INFO "Get service descriptor in CCT (${deployEndpointUrl})"

    httpResponse=$(CICDCD_AUTH_COOKIES="${cookies}" __invoqueService "GET" "${deployEndpointUrl}" ) && returnCode=0 || returnCode=1

    if [[ "${returnCode}" == 0 ]] ; then
        INFO "Service descriptor: ${cctService} installed"
        data=$(echo "${httpResponse}" | head -1 )
    else
        ERROR "Service descriptor: ${cctService} is not installed"
    fi
    echo "${data:-}"
    return "${returnCode}"
}

#################################
# Checks if an service descriptor is present in cct.
#
# Parameters:
#		CICDCD_SSO_URL              Envirenment variable with the url of login screen
#		AUTH_COOKIE           		Envirenment variable with atuhentication cookies, mandatory
#
#    param 1: template service in cct, i.e. microservice
#    param 2: templante service model in cct, i.e. cicdcd
#    param 3: version, opcional
#
isServiceDescriptorPublished() {
    local cctService=$1
    local cctModel=$2
    local cctVersion="${3:-}"

    local cct_base_url="${CICDCD_SSO_URL:-}"
    local cookies="${AUTH_COOKIE:-}"

    local data=""

    local returnCode=1

    data=$(CICDCD_AUTH_COOKIES="${cookies}" CICDCD_SSO_URL="${cct_base_url}" _getServiceDescriptor "$@") && returnCode=0 || returnCode=1

    if [[ "${returnCode}" == 0 ]] ; then
        INFO "Service ${cctService} with model ${cctModel} is published"
    else
        INFO "Service ${cctService} with model ${cctModel} is not published"
    fi

    return "${returnCode}"
}

#################################
# Internal functional
#
# Get next descriptor version from CCT by invoking the universe api and
# using a descriptor.
# To do that an auth cookie is provided in the shell variable AUTH_COOKIE.
#
# Parameters:
#		CICDCD_SSO_URL              Envirenment variable with the url of login screen
#		AUTH_COOKIE           		Envirenment variable with atuhentication cookies, mandatory
#
#    param 1: template service in cct, i.e. microservice
#    param 2: templante service model in cct, i.e. cicdcd
#
function _getNextDescriptorVersion {
    local cctService=$1
    local cctModel=$2
    local mandatoryArguments=2

    local cct_base_url="${CICDCD_SSO_URL:-}"
    local cookies="${AUTH_COOKIE:-}"
    local cctTimeout="${CICDCD_CCT_TIMEOUT:-0}"
    local dateMax=""

    local httpResponse=""
    local data=""
    local status_code=""
    local serviceId=""
    local nextDescriptorVersion=""

    local deployEndpointUrl=""

#    deployEndpointUrl="${cct_base_url}/service/deploy-api/universe/${cctService}/${cctModel}/versions"
    deployEndpointUrl="$(
        CCT_SERVICE=${cctService} \
        CCT_MODEL=${cctModel} \
            __getAPIEndpoint "APPLICATION_SERVICE_DESCRIPTOR_VERSION")"

    INFO "Get next service descriptor in CCT (${deployEndpointUrl})"

#	INFO "Calling this endpoint: ${deployEndpointUrl}"

    httpResponse=$(CICDCD_AUTH_COOKIES="${cookies}" __invoqueService "GET" "${deployEndpointUrl}") && returnCode=0 || returnCode=1

    if [[ "${returnCode}" == 0 ]] ; then
        data=$(echo "${httpResponse}" | head -1 )
        INFO "${data}"
        nextDescriptorVersion=$(echo "${data}" | jq  -r '
            max_by(.version
                | [splits("[.]")]
                | map(tonumber))
                | .version
                | [splits("[.]")]
                | to_entries
                | map({v:.value | tonumber , k:.key })
                | map(
                    select(.k==2) .v |= .+1
                        | .v | tostring
                    )
                | join(".") ' )

        INFO "Next version descriptor: ${nextDescriptorVersion}"

    else
        INFO "Service descriptor not install, default version set"
    fi
    echo "${nextDescriptorVersion:-0.5.0}"

}

#################################
# Publish a given application into CCT by invoking the deployment api and
# using a deployment descriptor. To do that an auth cookie can be privided in
# parameter number 4.
#
# Parameters:
#	CICDCD_SSO_URL              Envirenment variable with the url of login screen
#	CICDCD_SSO_USER_ID          Envirenment variable with SSO UserID
#	CICDCD_SSO_USER_PASSWORD    Envirenment variable with SSO User password
#	CICDCD_SSO_TENANT           Envirenment variable with SSO User tenantId, NONE by default
#	AUTH_COOKIE           		Envirenment variable with atuhentication cookies, opcional
#	CICDCD_CCT_TIMEOUT			Publish timeout
#	--serviceName				Service name, use for the update of the service
#   --publishTenant          	Reference to the Tenant where to publish/update/upgrade the service, NONE by default
#	--deploymentDescriptor		JSON deploy use to install/update/upgrade the service
#	--model           			CCT Model to use to install/upgrade the service. If not set, service is update
#	--version					CCT Version to use to install/upgrade the service. If not set, service is update
#	--service					CCT Service to use to install/upgrade the service. If not set, service is update
#	--serviceDescriptor			CCT Service descriptor, to publish in case of need
#
function publishApplication {
    local serviceName=""
    local publishTenant=""
    local deploymentDescriptor=""
    local model=""
    local version=""
    local service=""
    local serviceDescriptor=""
    local userSsoTenant="${CICDCD_SSO_TENANT:-}"
    local mandatoryArguments=6

    local cctTimeout="${CICDCD_CCT_TIMEOUT:-0}"
    local isTimeOut=false
    local isHealthy=false
    local dateMax=""

    local httpResponse=""
    local data=""
    local status_code=""
    local cookies=""
    local implicitServiceName=""
    local tempDeployedJson=""
    local isPublishedApp=""
    local isServicePublished=""

    local publishedModel=""
    local publishedService=""
    local publishedVersion=""

    local HELP_TEXT=" Publish (install, update or upgrade) a service
        USAGE:
            CICDCD_SSO_URL              Envirenment variable with the url of login screen
            CICDCD_SSO_USER_ID          Envirenment variable with SSO UserID
            CICDCD_SSO_USER_PASSWORD    Envirenment variable with SSO User password
            CICDCD_SSO_TENANT           Envirenment variable with SSO User tenantId, NONE by default
            AUTH_COOKIE           		Envirenment variable with atuhentication cookies, opcional
            --publishTenant          	Reference to the Tenant where to publish/update/upgrade the service, NONE by default
            --serviceName				Service name, use for the update of the service
            --deploymentDescriptor		JSON deploy use to install/update/upgrade the service
            --model           			CCT Model to use to install/upgrade the service. If not set, service is update
            --version					CCT Version to use to install/upgrade the service. If not set, service is update
            --service					CCT Service to use to install/upgrade the service. If not set, service is update
            --serviceDescriptor			CCT Service descriptor, to publish in case of need
    "

    options=$(getopt \
        --options h\? \
        --long publishTenant:,deploymentDescriptor:,model:,version:,serviceDescriptor:,service:,serviceName:,help \
        -- "$@")

    if [[ ${#@} -ne 0 ]] && [[ ${@#"--help"} = "" ]]; then
        printf -- "%s" "${HELP_TEXT}"
        return 0
    fi

    # fail if non option is specified
    if [[ -z ${options} ]] || [[ $# -eq 0 ]] ; then
        # something went wrong, getopt will put out an error message for us
        printf -- "%s" "${HELP_TEXT}"
        exit 1
    fi

    set -- ${options}

    while [[ $# -gt 0 ]] ; do
        case $1 in
            --publishTenant)
                publishTenant=${2:1:-1}
                shift
            ;;
            --deploymentDescriptor)
                deploymentDescriptor=${2:1:-1}
                shift
            ;;
            --model)
                model=${2:1:-1}
                shift
            ;;
            --version)
                version=${2:1:-1}
                shift
            ;;
            --service)
                service=${2:1:-1}
                shift
            ;;
            --serviceDescriptor)
                serviceDescriptor=${2:1:-1}
                shift
            ;;
            --serviceName)
                serviceName=${2:1:-1}
                shift
            ;;
            -h|--help|-\?)  printf -- "%s" "${HELP_TEXT}" ; exit 0 ;;
            (--)            ;;
            (-*)            printf "%s: error - unrecognized option %s" "$0" "$1" 1>&2 ; exit 1 ;;
            (*)
            ;;
        esac
        shift
    done

    if [[ -z ${deploymentDescriptor} ]] ; then
        ERROR "Json deploy is mandatory"
        exit 1
    fi

    implicitServiceName=$(jq -r '.general.serviceId' "${deploymentDescriptor}")
    if [[ "${implicitServiceName}" == null ]] ; then implicitServiceName="" ; fi
    : "${serviceName:=${implicitServiceName}}"

    if [[ -z ${serviceName} ]] ; then
        ERROR "Application name not defined in deployement descriptor and not passed as paramaeter, but it is mandatory."
        exit 1
    fi

    if [[ -n ${AUTH_COOKIE:-} ]] ; then
        cookies="${AUTH_COOKIE}"
    else
        cookies=$(
            CICDCD_SSO_USER_ID="${CICDCD_SSO_USER_ID}" \
            CICDCD_SSO_USER_PASSWORD="${CICDCD_SSO_USER_PASSWORD}" \
            CICDCD_SSO_URL="${CICDCD_SSO_URL}/login" \
            CICDCD_SSO_TENANT="${CICDCD_SSO_TENANT:-}" \
                login_CCT --rawcookies)
    fi

    if [[ -z ${CCT_API_VERSION:-} ]] ; then
        export CCT_API_VERSION=$(AUTH_COOKIE="${cookies}" CCT_URL="${CICDCD_SSO_URL}" __getAPIVersion)
    fi

    if [[ -n ${service} && -n ${model} ]] ; then
        $(AUTH_COOKIE="${cookies}" CICDCD_SSO_URL="${CICDCD_SSO_URL}" isServiceDescriptorPublished "${service}" "${model}" "${version:-}") && isServicePublished=true || isServicePublished=false

        if [[ "${isServicePublished}" == true ]] ; then
            INFO "Service descriptor exists. Continue deployement."
        elif [[ "${isServicePublished}" == false && -n "${serviceDescriptor}" ]] ; then
            INFO "Service descriptor not exists. Deploy service."
            AUTH_COOKIE="${cookies}" CICDCD_SSO_URL="${CICDCD_SSO_URL}" _installServiceDescriptor "${service}" "${model}" "${serviceDescriptor}" "${version:-}"
        else
            ERROR "Service not published, nothing to do"
            exit 1
        fi
    fi

    # INFO "serviceTenant: ${publishTenant}"
    data=$(
        AUTH_COOKIE="${cookies}" \
        CICDCD_SSO_URL="${CICDCD_SSO_URL}" \
        CICDCD_SERVICE_TENANT="${publishTenant}" \
            _getStatus "${serviceName}"
        ) && isPublishedApp=true || isPublishedApp=false

    if [[ "${isPublishedApp}" == true ]] ; then

        publishedService=$(echo "${data}" | jq -r '.service')
        publishedModel=$(echo "${data}" | jq -r '.model')
        publishedVersion=$(echo "${data}" | jq -r '.version')

        if [[ "${publishedVersion}" == "null" ]]; then
            publishedVersion=""
            INFO "publishedVersion null"
        fi

        INFO "Service value: ${service}"
        INFO "model value: ${model}"
        INFO "publishedModel value: ${publishedModel}"
        INFO "publishedService value: ${publishedService}"
        INFO "version value: ${version}"
        INFO "publishedVersion value: ${publishedVersion}"

        if [[ -n "${service:-}" && -n "${model}" && ( "${service:-}" != "${publishedService}" || "${model:-}" != "${publishedModel}"  || "${version:-}" != "${publishedVersion:-}" ) ]]; then
            INFO "Upgrade of ${serviceName} service"

            AUTH_COOKIE="${cookies}"  \
            CICDCD_SSO_URL="${CICDCD_SSO_URL}"  \
            CICDCD_SERVICE_TENANT="${publishTenant}"  \
                _upgradeApplication "${service}" "${model}" "${serviceName}" "${deploymentDescriptor}" "${version:-}"

        elif [[ "${serviceName}" != "${implicitServiceName}" ]] ; then
            ERROR "The service name passed as a parameter ${serviceName} is not the same as the service name passed in the Deployment descriptor file ${implicitServiceName}"
            exit 1
        else
            INFO "Update of ${serviceName} service"

            AUTH_COOKIE="${cookies}"  \
            CICDCD_SSO_URL="${CICDCD_SSO_URL}"  \
            CICDCD_SERVICE_TENANT="${publishTenant}"  \
                _updateApplication  "${serviceName}" "${deploymentDescriptor}"
        fi
    else
        if [[ -n "${service}" ]] && [[ -n "${model}" ]] ; then
            INFO "Install new service"

            AUTH_COOKIE="${cookies}"  \
            CICDCD_SSO_URL="${CICDCD_SSO_URL}"  \
            CICDCD_SERVICE_TENANT="${publishTenant}"  \
            CICDCD_CCT_TIMEOUT=${cctTimeout}  \
                _installApplication "${service}" "${model}" "${deploymentDescriptor}" "${version:-}"
        else
            ERROR "No Information, nothing to do"
            exit 1
        fi
    fi

    CICDCD_SERVICE_TENANT="${publishTenant}" \
    CICDCD_CCT_TIMEOUT=${cctTimeout} \
        healthCheckApp "${CICDCD_SSO_URL}" "${serviceName}" "${cookies}" && returncode=0 || returncode=$?

    if [[ "${returncode}" -eq 102 ]] ; then
        ERROR "Deployment failed for application ${serviceName} due timeout waiting for a healthy status!"
        exit 102
    else
        INFO "Deployment successfully performed for application ${serviceName}!"
    fi
}

#################################
# Unpublish a given application into CCT by invoking the deployment api and
# using a deployment descriptor.
#
# Parameters:
#	CICDCD_SSO_URL              Envirenment variable with the url of login screen
#	CICDCD_SSO_USER_ID          Envirenment variable with SSO UserID
#	CICDCD_SSO_USER_PASSWORD    Envirenment variable with SSO User password
#	CICDCD_SSO_TENANT           Envirenment variable with SSO User tenantId, NONE by default
#	AUTH_COOKIE           		Envirenment variable with atuhentication cookies, opcional
#	CICDCD_CCT_TIMEOUT			Publish timeout
#	--publishTenant          	Reference to the Tenant where to publish/update/upgrade the service, NONE by default
#	--serviceName				Mandatory Application Name
#
function unpublishApplication {
    local serviceName=""
    local publishTenant=""
    local userSsoTenant="${CICDCD_SSO_TENANT:-}"
    local cct_base_url="${CICDCD_SSO_URL:-}"

    local cctTimeout="${CICDCD_CCT_TIMEOUT:-0}"
    local isTimeOut=false
    local isPublishedApp=true
    local isUnpublishedSuccess=false
    local dateMax=""

    local httpResponse=""
    local data=""
    local cookies=""

    local HELP_TEXT=" Publish (install, update or upgrade) a service
        USAGE:
            CICDCD_SSO_URL              Envirenment variable with the url of login screen
            CICDCD_SSO_USER_ID          Envirenment variable with SSO UserID
            CICDCD_SSO_USER_PASSWORD    Envirenment variable with SSO User password
            CICDCD_SSO_TENANT           Envirenment variable with SSO User tenantId, NONE by default
            AUTH_COOKIE           		Envirenment variable with atuhentication cookies, opcional
            --publishTenant          	Reference to the Tenant where to publish/update/upgrade the service, NONE by default
            --serviceName				Mandatory Application Name
    "

    options=$(getopt \
        --options h\? \
        --long publishTenant:,serviceName:,help \
        -- "$@")

    if [[ ${#@} -ne 0 ]] && [[ ${@#"--help"} = "" ]]; then
        printf -- "%s" "${HELP_TEXT}"
        return 0
    fi

    # fail if non option is specified
    if [[ -z ${options} ]] || [[ $# -eq 0 ]] ; then
        # something went wrong, getopt will put out an error message for us
        printf -- "%s" "${HELP_TEXT}"
        exit 1
    fi

    set -- ${options}

    while [[ $# -gt 0 ]] ; do
        case $1 in
            --publishTenant)
                publishTenant=${2:1:-1}
                shift
            ;;
            --serviceName)
                serviceName=${2:1:-1}
                shift
            ;;
            -h|--help|-\?)  printf -- "%s" "${HELP_TEXT}" ; exit 0 ;;
            (--)            ;;
            (-*)            printf "%s: error - unrecognized option %s" "$0" "$1" 1>&2 ; exit 1 ;;
            (*)
            ;;
        esac
        shift
    done

    if [[ -z "${serviceName}" ]] ; then
        ERROR "Service name is mandatory"
        exit 1
    fi

    if [[ -n ${AUTH_COOKIE:-} ]] ; then
        cookies="${AUTH_COOKIE}"
    else
        cookies=$(
            CICDCD_SSO_USER_ID="${CICDCD_SSO_USER_ID}" \
            CICDCD_SSO_USER_PASSWORD="${CICDCD_SSO_USER_PASSWORD}" \
            CICDCD_SSO_URL="${CICDCD_SSO_URL}/login" \
            CICDCD_SSO_TENANT="${CICDCD_SSO_TENANT:-}" \
                login_CCT --rawcookies)
    fi

    if [[ -z ${CCT_API_VERSION:-} ]] ; then
        export CCT_API_VERSION=$(AUTH_COOKIE="${cookies}" CCT_URL="${CICDCD_SSO_URL}" __getAPIVersion)
    fi

    application=$(__sanitizedServiceID "${serviceName}" "${publishTenant}")
#    deployEndpointUrl="${cct_base_url}/service/deploy-api/deploy/uninstall?app=/${application}&force=true"
    deployEndpointUrl="$(APPLICATION=${application} __getAPIEndpoint "APPLICATION_UNINSTALL")"

    INFO "Destroying application ${serviceName} in CCT (${cct_base_url})"

    INFO "Calling this endpoint: ${deployEndpointUrl}"

    if [[ cctTimeout -gt 0 ]] ; then
        dateMax=$(( $(date +%s) + cctTimeout ))
        INFO "Uninstall application will be retry during ${cctTimeout} seconds, until $(date -d @${dateMax})."
    fi
#	set -x
    while
        data=$(
            AUTH_COOKIE="${cookies}" \
            CICDCD_SSO_URL="${cct_base_url}" \
            CICDCD_SERVICE_TENANT="${publishTenant}" \
                _getStatus "${serviceName}"
        ) && isPublishedApp=true || isPublishedApp=false

        if [[ "${isPublishedApp}" == true ]] ; then
            INFO "Uninstall application ${deployEndpointUrl}."
            httpResponse=$(CICDCD_AUTH_COOKIES="${cookies}" __invoqueService "DELETE" "${deployEndpointUrl}") && isUnpublishedSuccess=true || isUnpublishedSuccess=false
        fi
        [[ "${dateMax}" -lt $(date +%s) ]] && isTimeOut=true || isTimeOut=false
        [[ "${isTimeOut}" == false && "${isUnpublishedSuccess}" == false && "${isPublishedApp}" == true ]]
    do
        sleep 5
    done

    if [[ -n "${dateMax}" && "${isTimeOut}" == true ]] ; then
        ERROR "Unpublish of ${serviceName} failed due to timeout"
        returnCode=1
    elif [[ "${isPublishedApp}" == true ]] ; then
        ERROR "Application ${serviceName} still published"
        returnCode=1
    else
        INFO "Unpublish of ${serviceName} successfully performed"
        returnCode=0
    fi

#	set +x
}

#################################
# Legacy function, used unpublishApplication instead.
#
# Destroy an application in cct. If 3 params are given, then the
# last one is spected to be the auth cookie in the format expected. If 4 params
# are given, then user and password are used to retrieve the auth cookie by
# invoking login_CCT func.
#
# Parameters:
#		CICDCD_SSO_TENANT           Envirenment variable with SSO User tenantId, NONE by default
#		CICDCD_SERVICE_TENANT       Envirenment variable with tenant name, if exist
#
#    param 1: cct base url. I.e. https://eos.client.domainname.com
#    param 2: application name to destroy. I.e. hello/hello-world
#
#    if cookie provided:
#    param 3: auth cookie
#
#    if user and password provided:
#    param 3: user identification
#    param 4: password

function destroyApplication {
    local cct_base_url=$1
    local application=$2

    local userSsoTenant="${CICDCD_SSO_TENANT:-}"
    local serviceTenant="${CICDCD_SERVICE_TENANT:-}"
    local mandatoryArguments=2

    if [[ "$#" -ge "${mandatoryArguments}" ]] ; then
        shift "${mandatoryArguments}"
        cookies=$(CICDCD_SSO_TENANT="${userSsoTenant}" __retrieveCookie "${cct_base_url}" "$@")
    fi

    CICDCD_SSO_URL="${cct_base_url}" \
    CICDCD_CCT_TIMEOUT=300 \
    AUTH_COOKIE="${cookies}" \
        unpublishApplication --serviceName "${application}" --publishTenant "${serviceTenant}"
}

#################################
# Legacy function, used publishApplication instead.
#
# Install a given application into CCT by invoking the deployment api and
# using a deployment descriptor. It also need the service name template and
# its corresponding model as params. To do that an auth cookie can be privided
# in parameter number 5. Also can be provided user and password in params 5
# and 6.
#
# Parameters:
#    param 1: cct base url. I.e. https://eos.client.domainname.com
#    param 2: template service in cct, i.e. microservice
#    param 3: templante service model in cct, i.e. cicdcd
#    param 4: deployment descriptor file path
#
#    if cookie provided:
#    param 5: auth cookie
#
#    if user and password provided:
#    param 5: user identification
#    param 6: password

function installApplication {
    local cct_base_url=$1
    local cctService=$2
    local cctModel=$3
    local deploymentDescriptor=$4
    local cctVersion=$5
    local userSsoTenant="${CICDCD_SSO_TENANT:-}"
    local publishTenant="${CICDCD_SERVICE_TENANT:-}"
    local mandatoryArguments=5

    local cookies=""

    if [[ "$#" -ge "${mandatoryArguments}" ]] ; then
        shift "${mandatoryArguments}"
        cookies=$(CICDCD_SSO_TENANT="${userSsoTenant}" __retrieveCookie "${cct_base_url}" "$@")
    fi

    if [[ "${cctVersion}" == "NONE" ]] ; then
        cctVersion=""
    fi

    CICDCD_SSO_URL="${cct_base_url}" \
    CICDCD_CCT_TIMEOUT=300 \
    AUTH_COOKIE="${cookies}" \
        publishApplication \
            --service "${cctService}" \
            --model "${cctModel}" \
            --deploymentDescriptor "${deploymentDescriptor}" \
            --version "${cctVersion}" \
            --publishTenant "${publishTenant}"
}

#################################
# Legacy function, used publishApplication instead.
#
# Update a given application into CCT by invoking the deployment api and
# using a deployment descriptor. To do that an auth cookie can be privided in
# parameter number 4. Also can be provided user and password in params 4 and 5.
#
# Parameters:
#    param 1: cct base url. I.e. https://eos.client.domainname.com
#    param 2: application name, with its groupId if necesaary. I.e. hello/hello-world
#    param 3: deployment descriptor file path
#
#    if cookie provided:
#    param 4: auth cookie
#
#    if user and password provided:
#    param 4: user identification
#    param 5: password
#
function updateApplication {
    local cct_base_url=$1
    local application=$2
    local deploymentDescriptor=$3
    local userSsoTenant="${CICDCD_SSO_TENANT:-}"
    local publishTenant="${CICDCD_SERVICE_TENANT:-}"
    local mandatoryArguments=3

    local cookies=""

    local deployEndpointUrl=""
    
    if [[ "$#" -ge "${mandatoryArguments}" ]] ; then
        shift "${mandatoryArguments}"
        cookies=$(CICDCD_SSO_TENANT="${userSsoTenant}" __retrieveCookie "${cct_base_url}" "$@")
    fi

    CICDCD_SSO_URL="${cct_base_url}" \
    CICDCD_CCT_TIMEOUT=300 \
    AUTH_COOKIE="${cookies}" \
        publishApplication  \
            --serviceName "${application}"  \
            --deploymentDescriptor "${deploymentDescriptor}" \
            --publishTenant "${publishTenant}"
}
