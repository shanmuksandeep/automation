#!/bin/bash
####################################################################################
# Script name     : tiles_upgrade.sh
# Usage           : bash tiles_upgrade.sh <foundation>
# Description     :
#
#                   log function - params
#                   0 - Success
#                   1 - Failure
#                   2 - Custome message or flag
# Author          :
# Date            :
# Change history  :
# modified metrics deployment name
#
#####################################################################################
set -o pipefail
set -x
mdate=`date +%m%d%Y%H%M%S`
report () {
   val=$( [ "$1" == "0" ] && echo "Success" || echo "Failed")
   printf "%-30s|   %-30s|    %-20s|    %s\n" $foundation $pipeLineName $action $val  >> ${foundation}_run_report_${val}_${mdate}.txt
}
log () {
    if [ $2 -eq 0 ]
    then
       message="OK"
       [[ "$3" == "nolog" ]] && printf "\r\033[2K [ \033[00;32m${message}\033[0m ] [${foundation}][`date`] - $1\n"
    elif [ $2 -eq 2 ]
    then
       message=$3
       [[ "$3" == "nolog" ]] &&  message=$4
       [[ "$3" == "nolog" ]] && printf "\r\033[2K [ \033[00;32m${message}\033[0m ] [${foundation}][`date`] - $1\n"
    else
       message="ERR"
       [[ "$3" == "nolog" ]] && printf "\r\033[2K [ \033[00;31m${message}\033[0m ] [${foundation}][`date`] - $1\n"
    fi
    val=$3
    lmesg=${val:-"print"}
    [ "$lmesg" != "nolog" ] && printf "\r\033[2K [ \033[00;32m${message}\033[0m ] [${foundation}][`date`] - $1\n" | tee -a ${logFileName}.log
}
usage () {
    printf "\r\033[2K [\033[0;31mUsage\033[0m] $1 \n"
    exit 1
}
buildParams () {
   command=""
   pName=$1
   dKey=$2
   dVer=$3
   action=$4
   pName=$(date +%B)-${pName}
   echo "Deployment name : $pName - Version: $dVer"
   [ $action == "DELETE" ] && command="./fly -t ${foundation} destroy-pipeline -p ${pName}"
   [ $action == "CREATE" ] && command="./fly -t ${foundation} set-pipeline -p ${pName} -c ./automation/upgrade-tile/pipeline.yml -l ./automation/tiles-upgrade/parameters/${dKey}.yml -l ./pipeline-script/ci/credentials/credentials.yml -l ./pipeline-script/ci/foundations/${foundation}.yml -v product_version_regex=${dVer} -n"
   [ $action == "UNPAUSE" ] && command="./fly -t ${foundation} unpause-pipeline --pipeline ${pName}"
   echo "Command: $command"
   log "Command : $command" 2 "Running"
   eval ${command}
   if [ $? -eq 0 ]
   then
      log "Command : $command" 0
      [ $action != "UNPAUSE" ] && report 0
      if [ $action == "UNPAUSE" ]
      then
         checkforCompletion ${pName}
         command="./fly -t ${foundation} pause-pipeline --pipeline ${pName}"
         eval $command
         log "Pipline - $pipeName is paused" 0
      fi
   else
      report 1
      log "Command : $command" 1
   fi
}
checkforCompletion () {
   pipeName=$1
   while [ 1 ]
   do
      sleep 10
      rStatus=$(./fly -t ${foundation} builds | grep -w $pipeName | awk '{print $4}')
      if [ "$rStatus" == "succeeded" ]
      then
         log "Pipeline - $pipeName success" 0
         report 0
         break;
      elif [ "$rStatus" == "aborted" ] || [ "$rStatus" == "failed" ] || [ "$rStatus" == "errored" ]
      then
         log "Pipeline - $pipeName failed" 1
         report 1
        break;
      fi
   done
}
declare -A FVERSIONS OPS_VERSIONS PIPLINES
FVERSIONS=(
[opsman]="p-bosh"
[ERT]="cf"
[RabbitMQ]="p-rabbitmq"
[Redis]="p-redis"
[Metrics]="apmPostgres"
[SSO]="Pivotal_Single_Sign-On_Service"
[NewRelicNozzle]="nr-firehose-nozzle"
[NewRelicBroker]="newrelic-broker"
[SCS]="p-spring-cloud-services"
[SplunkNozzle]="splunk-nozzle"
[CloudCache]="p-cloudcache"
[MySQLv2]="pivotal-mysql"
[Scheduler]="p-scheduler"
[SCDF]="p-dataflow"
[Healthwatch]="p-healthwatch"
[NewRelicDotNetBuildpack]="new-relic-dotnet-buildpack"
)
#######  Main progrem starts ################
foundation=$FOUNDATION
unPauseFlag=$UNPAUSE_FLAG
logFileName="${foundation}_tile_upgrade_${mdate}"
uaac target [https://$OPS_MANAGER_HOSTNAME/uaa]https://$OPS_MANAGER_HOSTNAME/uaa --skip-ssl-validation
uaac token client get $UAA_CLIENT_ID -s $UAA_CLIENT_SECRET
export CFOPS_ADMIN_TOKEN=$(uaac context | grep ".*access_token: " | sed -n -e "s/^.*access_token: //p")
#delete the ops manager sessions
log "Command: Deleting Ops Manager sessions..." 2 "nolog" "Running"
curl --noproxy '*' "[https://$OPS_MANAGER_HOSTNAME/api/v0/sessions]https://$OPS_MANAGER_HOSTNAME/api/v0/sessions" -X DELETE -H "Authorization: Bearer $CFOPS_ADMIN_TOKEN" -H "Content-Type: application/x-www-form-urlencoded" --insecure
if [ $? -ne 0 ]
then
   log "Command: Deleting Ops Manager sessions..." 1 "nolog"
else
   log "Command: Deleted Ops Manager sessions..." 0 "nolog"
fi
wget -O fly ${CONCOURSE_HOSTNAME}/api/v1/cli?arch=amd64\&platform=linux
[[ $? -ne 0 ]] && log "Problem in downloading the fly tool" 1
chmod +x ./fly
./fly --version
[[ -f temp_${foundation}_versions.yml ]] && rm -f temp_${foundation}_versions.yml
cat automation/foundation_versions.yml | grep "^$foundation" | grep ":" | grep -v opsman | sed 's/'$foundation'_//g' | while IFS=':' read deploymentName depVersion
do
    echo "Deployment: $deploymentName - Version: $depVersion"
    echo "$deploymentName:$depVersion" >> temp_${foundation}_versions.yml
done
if [ -s temp_${foundation}_versions.yml ]
then
   :
else
   echo "ERROR: No version found for - ${foundation} in foundation_versions.yml file"
   exit 1
fi
uaac target [https://$OPS_MANAGER_HOSTNAME/uaa]https://$OPS_MANAGER_HOSTNAME/uaa --skip-ssl-validation
uaac token client get $UAA_CLIENT_ID -s $UAA_CLIENT_SECRET
export CFOPS_ADMIN_TOKEN=$(uaac context | grep ".*access_token: " | sed -n -e "s/^.*access_token: //p")
# fetch the installed product versions in the Ops Manager
curl -s --noproxy '*' -X GET "[https://$OPS_MANAGER_HOSTNAME/api/v0/deployed/products]https://$OPS_MANAGER_HOSTNAME/api/v0/deployed/products" -H "Authorization: Bearer $CFOPS_ADMIN_TOKEN" -H "Content_Type: application/json" --insecure | jq '.[] | .installation_name + ":" + .product_version' > ops_versions.json
if [ $? -ne 0 ]
then
   log "Problem in executing curl command" 1
   exit 1
fi
# display the current ops manager deployment versions
if [ -s ops_versions.json ]
then
   cat ops_versions.json
else
   log "Problem in generating the OPS MGR versions" 1
   exit 1
fi
checkCount=$(grep -c ":" ops_versions.json)
if [[ $checkCount -gt 1 ]]
then
   :
else
   log "Problem in generating the OPS MGR versions" 1
   exit 1
fi
#delete the ops manager sessions
log "Command: Deleting Ops Manager sessions..." 2 "nolog" "Running"
curl --noproxy '*' "[https://$OPS_MANAGER_HOSTNAME/api/v0/sessions]https://$OPS_MANAGER_HOSTNAME/api/v0/sessions" -X DELETE -H "Authorization: Bearer $CFOPS_ADMIN_TOKEN" -H "Content-Type: application/x-www-form-urlencoded" --insecure
if [ $? -ne 0 ]
then
   log "Command: Deleting Ops Manager sessions..." 1 "nolog"
else
   log "Command: Deleted Ops Manager sessions..." 0 "nolog"
fi
count=0
./fly -t ${foundation} login -c ${CONCOURSE_HOSTNAME} -u ${CONCOURSE_USERID} -p ${CONCOURSE_PASS} -n ${CONCOURSE_TEAMSID}
if [ $? -ne 0 ]
then
   log "Problem in login to pipeline using fly command" 1
   exit 1
fi
for key in "${!FVERSIONS[@]}"
do
   fver=$(grep "${key}_" temp_${foundation}_versions.yml | awk -F':' '{print $2}')
   opsver=$(egrep "${FVERSIONS[$key]}-|${FVERSIONS[$key]}:" ops_versions.json  | awk -F':' '{print $2}' | sed -e 's/\"//g')
   opsver=${opsver%-*}
   t_fver=$(echo $fver | tr -d '.' | tr -d '[:space:]')
   t_opsver=$(echo $opsver | tr -d '.' )
   temp_fver=${fver%%.*}
   temp_opsver=${opsver%%.*}
   temp_sec_fver=$(echo $fver | tr -d '[:space:]' | cut -d'.' -f1-2 | tr -d '.')
   temp_sec_opsver=$(echo $opsver | tr -d '[:space:]' | cut -d'.' -f1-2 | tr -d '.')
   if [[ $t_fver -gt $t_opsver ]] || [[ $temp_fver -gt $temp_opsver ]] || [[ $temp_sec_fver -gt $temp_sec_opsver ]]
   then
      pipeLineName="${foundation}-Stage-Tile-${key}"
      echo "${key} - $fver"
      #buildParams $pipeLineName $fver  DELETE
      #eval ${command}
      buildParams ${pipeLineName} ${key} $fver CREATE
      if [ "$unPauseFlag" == "true" ]
      then
        buildParams ${pipeLineName} ${key} $fver UNPAUSE
      fi
      ((count=count+1))
   fi
done
sFile=${foundation}_run_report_Success_${mdate}.txt
eFile=${foundation}_run_report_Failed_${mdate}.txt
if [ -s $sFile ]
then
   sattach=" -F file=@${sFile}"
fi
if [ -s $eFile ]
then
   eattach=" -F file=@${eFile}"
fi
mattach=${sattach}${eattach}
log "Command: sending the email ..." 2 "nolog" "Running"
status=$(curl --noproxy '*' -X POST  -o - -s -w "%{http_code}\n"  https://syfemailutility-dev.app.dev.phx.pcf.syfbank.com/sendEmail -F model='{"toEmail":"simmy.xavier@syf.com","subject":"'$foundation' : Foundation deployment for '`date +%b-%Y`' status","content":"<html><p> '$foundation' foundation deployment has been completed for '`date +%b-%Y`' and for more status please refer the attachments.<br/></p></html>","fromEmail":"PCF.Test-Results@syf.com"}' ${mattach})
if [ "$status" != "success200" ]
then
   log "Command: sending the email. Error - $status" 1 "nolog"
else
   log "Command: sending the email ..." 0 "nolog"
fi
[[ $count -eq 0 ]] && log "all version are up to date" 0 "nolog"
exit 0