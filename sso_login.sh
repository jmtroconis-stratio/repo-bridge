#!/bin/bash

SPARTA_UI_URI=https://gts-sparta.dev.onetrade.corp/gts-sparta
USERLOGIN=sparta
PASSWD=stratio
TENANT=gts
TICKET_FILE=/tmp/response-sparta.txt

function filter_jsessionid_cookie() {
    RET_VALUE=$(echo $1 \
        | grep -oE "JSESSIONID=[^;]+" \
        | sed "s/JSESSIONID=//g")
    echo $RET_VALUE
}

function filter_execution_value() {
    RET_VALUE=$(echo $1  \
        | grep -oE "\"execution\" value=\"[^<>]+\"" \
        | grep -oE "value=\"[^\"]+\"" \
        | sed "s/value=//g" \
        | sed "s/\"//g" \
        | sed "s/\//%2F/g" \
        | sed "s/+/%2B/g" \
        | sed "s/=/%3D/g")
     echo $RET_VALUE
}

function filter_lt_value() {
    RET_VALUE=$(echo $1 \
        | grep -oE "\"lt\" value=\"[^<>]+\"" \
        | grep -oE "value=\"[^\"]+\"" \
        | sed "s/value=//g" \
        | sed "s/\"//g")
    echo $RET_VALUE
}

function filter_ticket_value() {
    RET_VALUE=$(echo $1 \
        | grep -oE "ticket[^ ]+" \
        | sed "s/ticket=//g" \
        | grep -oE "[^ ]+" \
        | tr -d "\r")
    echo $RET_VALUE
}

function filter_user_value() {
    RET_VALUE=$(echo $1 \
        | grep -oE "user=[a-z0-9\-]+" \
        | sed "s/user=//g")
   echo $RET_VALUE
}

############## Login
#
# login
#     INPUTS:
#           1. SPARTA_UI_URI -> https://sparta.stratio-ey-wavespace.com/sparta
#           2: User_id with permission to execute CCT API -> admin
#           3: User Password -> 1234
#           4: Tenant -> NONE
#     OUTPUT:
#            a file located in $TICKET_FILE with the user ticket to access Sparta API

# Find sso login url from Sparta UI redirection url
#echo "[DEBUG] SPARTA_UI_URI: $SPARTA_UI_URI"

EFFECTIVE_URL=$(curl -k -s -L $SPARTA_UI_URI -w 'url_effective=%{url_effective}')
#echo "[DEBUG] EFFECTIVE_URL: $EFFECTIVE_URL"
SPARTA_LOGIN_URI=$(echo $EFFECTIVE_URL \
                | grep -oE 'url_effective=https?://[^ ]+' \
                | grep -oE 'https?://[^ ]+' \
                | head -n 1)

if [ $SPARTA_UI_URI == $SPARTA_LOGIN_URI ]
then
  echo "[ERROR] Could not retrieve a valid sso login url: $SPARTA_LOGIN_URI"
  exit 1
fi

echo "[INFO] Retrieved Sso Login Url: $SPARTA_LOGIN_URI"


AUTHORIZE_RESPONSE=$(curl -X GET $SPARTA_LOGIN_URI -k  -i -s -w 'http_status=(%{http_code})')
echo "[DEBUG] AUTHORIZE_RESPONSE: $AUTHORIZE_RESPONSE"


HTTP_STATUS_CODE=$(echo $AUTHORIZE_RESPONSE \
                | grep -oE "http_status=\([0-9]+\)" \
                | grep -oE "[0-9]+" \
                | head -n 1)

#echo "[DEBUG] HTTP_STATUS_CODE: $HTTP_STATUS_CODE"

if [ $HTTP_STATUS_CODE -ne 200 ]
then
  return 1
fi

JSESSIONID=$(filter_jsessionid_cookie "$AUTHORIZE_RESPONSE")

echo "[DEBUG] JSESSIONID: $HTTP_STATUS_CODE"

EXECUTION=$(filter_execution_value "$AUTHORIZE_RESPONSE")

LT=$(filter_lt_value "$AUTHORIZE_RESPONSE")

TICKET_RESPONSE=$(curl -X POST $SPARTA_LOGIN_URI -k -i -s -w 'http_status=(%{http_code})' -H "Cookie: JSESSIONID=$JSESSIONID" --data "lt=$LT&execution=$EXECUTION&_eventId=submit&username=$USERLOGIN&password=$PASSWD&tenant=$TENANT")

TICKET=$(filter_ticket_value "$TICKET_RESPONSE")

LOGIN_RESPONSE=$(curl -X GET "$SPARTA_UI_URI/login?code=$TICKET" -k -i -s -w 'http_status=(%{http_code})' --compressed)

USER_TICKET=$(filter_user_value "$LOGIN_RESPONSE")

echo "[DEBUG] USER_TICKET: $USER_TICKET"

echo $USER_TICKET > $TICKET_FILE
