#!/bin/bash
if [ "x"$1 = "x" ]; then
	echo "please input VERSION name !!!"
	exit
fi
VERSION=$1
DIR=`dirname $VERSION`

cd $DIR
commit_ts=`git log -1 --format="%ct"`
commit_time=`date -d@$commit_ts +"%Y%m%d"` #commit time
current_time=`date +"%Y%m%d"` #build time
git_version=`git log -1 --format="%h"` #commit id
cd - >/dev/null 2>&1

arch_info="sw_64"
GV="\-$arch_info(commit-$git_version)"
str="commit"
result=`sed -n "/${str}/p" $VERSION`
if [ -z "$result" ]
    then
        sed -i s/$/$GV/ $VERSION
    else
        sed -i 's/\-.*//' $VERSION
        sed -i s/$/$GV/ $VERSION
fi

