#!/usr/bin/env bash
# set -x

echo Using this deployment descriptor file: ./deploymentDescriptor-dev.json with this content: 
cat ./deploymentDescriptor.json 
echo '' 

. cct_deploy_utils.sh 

CICDCD_SSO_URL="https://admin.sgcto-int.stratio.com" CICDCD_SSO_USER_ID="admin" CICDCD_SSO_USER_PASSWORD="1234" CICDCD_CCT_TIMEOUT=300 publishApplication --service microservice --model cicdcd-secret --deploymentDescriptor ./deploymentDescriptor.json --version "0.7.6"

#CICDCD_SSO_URL="https://bootstrap.golf.hetzner.stratio.com" CICDCD_SSO_USER_ID="admin" CICDCD_SSO_USER_PASSWORD="1234" CICDCD_CCT_TIMEOUT=300 publishApplication --service microservice --model cicdcd-secret --deploymentDescriptor ./deploymentDescriptor.json --version "0.7.1-SNAPSHOT"

#CICDCD_SSO_URL="https://bootstrap.golf.hetzner.stratio.com" CICDCD_SSO_USER_ID="admin" CICDCD_SSO_USER_PASSWORD="1234" CICDCD_CCT_TIMEOUT=300 publishApplication --service front --model cicdcd-test-ha --deploymentDescriptor ./deploymentDescriptor.json --version "0.7.1-SNAPSHOT"
