## openvpn server (alpine)
Dockerfile for openvpn server, buile on Alpine linux.

Support easy list|create|delete client config

---------
# Licensing
ovpnd is licensed under the Apache License, Version 2.0. See
[LICENSE](https://github.com/binave/ovpnd/blob/master/LICENSE) for the full
license text.

import:
* [alpine linux](https://alpinelinux.org/)
* [openvpn](http://github.com/openvpn/openvpn)
* [easy-rsa](https://github.com/OpenVPN/easy-rsa)

---------

build

```sh

docker build --tag binave/ovpnd:2.4.9-alpine .

```

run

```sh

# run
docker run \
    --detach \
    --name openvpnd \
    --restart always \
    --cap-add NET_ADMIN \
    --volume /opt/openvpn:/etc/openvpn \
    --publish 1194:1194/udp \
    binave/ovpnd:2.4.9-alpine ovpnd start -cn 10.0.1.2

```

user config

```sh

# list all user with create datetime
docker exec -t openvpnd ovpnd list

# get password, Recommended remeber and remove it
docker exec -t openvpnd cat $(docker logs openvpnd 2>&1 | awk -F \' '/pass phrase/{print $2}')
#'

# add user1 with password
docker exec -it openvpnd ovpnd add user1

# get user1 config
docker exec -t openvpnd ovpnd get user1 > user1.ovpn

# del user1 with password
docker exec -it openvpnd ovpnd del user1

```

help
```sh

docker exec -it openvpnd ovpnd --help

docker exec -it openvpnd ovpnd start --help

```


alias ovpnd

```sh
cat >> ~/.bash_profile <<EOF

alias ovpnd='docker exec -it openvpnd ovpnd'

EOF

```

env|description|default
---|---|---
OVER_CONF_D|config path|`/etc/openvpn`
OVER_REQ_COUNTRY|rsa country|`CN`
OVER_REQ_PROVINCE|rsa province|`BEIJING`
OVER_REQ_CITY|rsa city|`BEIJING`
OVER_REQ_ORG|rsa org|`Copyleft Certificate Co`
OVER_REQ_EMAIL|rsa email|`me@example.net`
OVER_REQ_OU|rsa organizational unit|`My Organizational Unit`
OVER_CRL_DAYS|CRL expire days|`3650`
