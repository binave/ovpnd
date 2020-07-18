#!/bin/bash
# commit 'ovpnd.sh' at Dockerfile

sed -i ':1;N;$!b1;s@[0-9A-Za-z/+]\{76\}[[:space:]][^|]\+@'"`

    gzip -c ${0%/*}/ovpnd.sh | base64 | awk '{print $0 " \\\\\\\\\\\\"}'

`"\n'@' ${0%/*}/Dockerfile
