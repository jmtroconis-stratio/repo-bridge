#!/usr/bin/env bash
set -e

if [ "$#" -ne 2 ]; then
    echo "usage: $0 stratio_repo_url santander_repo_url" >&2
    exit 1
fi

STRATIO_REPO="$1"
SANTANDER_REPO="$2"
REPOS_INTEGRATION_BRANCH="santander-develop"

#if [[ "$STRATIO_REPO" != *Stratio* ]]
#    then
#    echo "First argument should be a repository url from Stratio GitHub (https://github.com/Stratio)"
#	exit 1
#fi

## TODO *********************************************************** github.alm.europe.cloudcenter.corp
#if [[ "$SANTANDER_REPO" != *Stratio* ]]
#    then
#    echo "Second argument should be a repository url from Santander GitHub (https://github.alm.europe.cloudcenter.corp/sgt-globaltradeservices)"
#	exit 1
#fi

echo ""
echo "********************************************************************************************************************************************"
echo "You are about to synchonize Git repository changes:"
echo "- From master branch in Stratio repository: '$STRATIO_REPO'"
echo "- To develop branch in Santander repository: '$SANTANDER_REPO'"
echo ""
echo "Before executing the script take into consideration the following requirements:"
echo "- The version of the application in master branch of Stratio GitHub repository ***MUST BE A SNAPSHOT VERSION***. Example: 0.0.0-SNAPSHOT"
echo "- The version of the application in master branch of Stratio GitHub repository will be the version used to deploy in Santander environment."
echo "********************************************************************************************************************************************"
echo ""
read -p "Are you sure (y/n)? " -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    echo "STEP 1/3 - Update Stratio integration branch $REPOS_INTEGRATION_BRANCH with Santander develop state"
    WORKDIR="$(mktemp -d)"
    cd "${WORKDIR}"
    git clone --single-branch --origin santander --branch develop $SANTANDER_REPO .
    git checkout -b $REPOS_INTEGRATION_BRANCH
    git remote add stratio $STRATIO_REPO
    git push stratio $REPOS_INTEGRATION_BRANCH
    cd .. && rm -rf "${WORKDIR}"
	
    echo ""
    echo "STEP 2/3 - Merge into Stratio integration branch $REPOS_INTEGRATION_BRANCH changes in master. Application version in master will be used in GitHub Santander (should be a SNAPSHOT version)"
    WORKDIR="$(mktemp -d)"
    cd "${WORKDIR}"
    git clone --origin stratio $STRATIO_REPO .
    git checkout master
	masterVersion=$(grep -oPm1 "(?<=<version>)[^<]+" "pom.xml")
    git checkout $REPOS_INTEGRATION_BRANCH
	git merge -X theirs --allow-unrelated-histories -m "New application changes from Stratio version ${masterVersion}" master
	integrationVersion=$(grep -oPm1 "(?<=<version>)[^<]+" "pom.xml")
	# If integration branch santander-stratio is not -SNAPSHOT is a promotion (else if being re-run the script)
	if [[ "$integrationVersion" != *-SNAPSHOT ]]
	then
		newProjectVersion="${masterVersion}-SNAPSHOT"
		echo "[INFO] Changing version from $masterVersion to $newProjectVersion"
		LN=$(grep -n "<version>" pom.xml | head -1 | awk -F ":" '{print $1}')
		sed -i "$LN s/$masterVersion/$newProjectVersion/" pom.xml
		git commit pom.xml -m "Set app version to ${newProjectVersion}"
	fi
    git push stratio $REPOS_INTEGRATION_BRANCH
    cd .. && rm -rf "${WORKDIR}"

    echo ""
    echo "STEP 3/3 - Publishing Stratio application changes to GitHub Santander into develop branch"
    WORKDIR="$(mktemp -d)"
    cd "${WORKDIR}"
    git clone --single-branch --origin stratio --branch $REPOS_INTEGRATION_BRANCH $STRATIO_REPO .
    git checkout -b develop
    git remote add santander $SANTANDER_REPO
    git push santander develop
    cd .. && rm -rf "${WORKDIR}"
else
    echo "ABORTED."
    exit 1
fi

echo ""
echo "Done."
