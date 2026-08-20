#!/bin/sh
if [ -n "$1" ];then
    grep -r "$1" * --exclude-dir=build --exclude-dir=roms --exclude=tags --color  --exclude-dir=build-org --exclude-dir=docs --exclude=configure --exclude-dir=capstone --exclude-dir=tests --exclude-dir=bsd-user --exclude-dir=meson --exclude=meson.build --exclude-dir=pc-bios --exclude-dir=scripts --exclude-dir=slirp
else
    echo "grep XXX"
fi

