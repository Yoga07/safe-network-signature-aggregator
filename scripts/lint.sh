#!/bin/bash

if egrep --exclude=\*.sh --exclude=CHANGELOG.md --exclude-dir=.git --exclude-dir=target -Rinw ../ -e '\<(unwrap|expect|panic|TODO|FIXME)\>'; then
  echo "***** MATCHES FOUND ******"
  exit 1
else
  echo "No matches to the specified string(s) found"
  exit 0
fi
