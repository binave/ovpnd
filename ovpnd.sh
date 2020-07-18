#!/bin/bash

# openvpn daemon

# convert CIDR Prefix (e.g. 1.1.1.0/24) to Subnet Mask (e.g. 1.1.1.0 255.255.255.0)
# see https://doc.m0n0.ch/quickstartpc/intro-CIDR.html
_CIDR_prefix2subnet_mask() {
    [ "$1" ] || return 1;
    set ${1/\// };

    local submask i=0 octets=$(($2 / 8)) \
        sub_octet=$((256 - 2 ** (8 - ($2 % 8) ) ));

    for ((; i < 4; i += 1))
    do
        if [ $i -lt $octets ]; then
            submask+=".255";

        elif [ $i == $octets ]; then
            submask+=".$sub_octet";

        else
            submask+=".0"

        fi
    done
    printf "$1 ${submask:1}"

}

# convert Subnet Mask (e.g. 1.1.1.0 255.255.255.0) to CIDR Prefix (e.g. 1.1.1.0/24)
_subnet_mask2CIDR_prefix() {
    [ "$2" ] || return 1;

    function _exponent() {
        local base=$1 power=2 exponent=0;
        while [ $((base /= $power)) -gt 0 ]; do
            ((exponent += 1));
        done
        printf $exponent;

    }

    local mask prefix=0
    for mask in ${2//\./ }; do
        (( prefix += 8 - $(_exponent $((256 - $mask))) ))
    done
    printf $1/$prefix

}


# $OVER_CONF_D/conf/server.conf
_server_conf () {
    printf "#################################################
# Sample OpenVPN 2.0 config file for            #
# multi-client server.                          #
#                                               #
# This file is for the server side              #
# of a many-clients <-> one-server              #
# OpenVPN configuration.                        #
#                                               #
# OpenVPN also supports                         #
# single-machine <-> single-machine             #
# configurations (See the Examples page         #
# on the web site for more info).               #
#                                               #
# This config should work on Windows            #
# or Linux/BSD systems.  Remember on            #
# Windows to quote pathnames and use            #
# double backslashes, e.g.:                     #
# 'C:\\\\\Program Files\\\\\OpenVPN\\\\\config\\\\\\\foo.key' #
#                                               #
# Comments are preceded with '#' or ';'         #
#################################################

# Which TCP/UDP port should OpenVPN listen on?
# If you want to run multiple OpenVPN instances
# on the same machine, use a different port
# number for each one.  You will need to
# open up this port on your firewall.
port ${server_port:-1194}

# TCP or UDP server?
proto ${server_proto:-udp}

# 'dev tun' will create a routed IP tunnel,
# 'dev tap' will create an ethernet tunnel.
# Use 'dev tap0' if you are ethernet bridging
# and have precreated a tap0 virtual interface
# and bridged it with your ethernet interface.
# If you want to control access policies
# over the VPN, you must create firewall
# rules for the the TUN/TAP interface.
# On non-Windows systems, you can give
# an explicit unit number, such as tun0.
# On Windows, use 'dev-node' for this.
# On most systems, the VPN will not function
# unless you partially or fully disable
# the firewall for the TUN/TAP interface.
dev ${server_device:-tun0}

# SSL/TLS root certificate (ca), certificate
# (cert), and private key (key).  Each client
# and the server must have their own cert and
# key file.  The server and all clients will
# use the same ca file.
#
# See the 'easy-rsa' directory for a series
# of scripts for generating RSA certificates
# and private keys.  Remember to use
# a unique Common Name for the server
# and each of the client certificates.
#
# Any X509 key management system can be used.
# OpenVPN can also use a PKCS #12 formatted key file
# (see 'pkcs12' directive in man page).
ca $EASYRSA_PKI/ca.crt
cert $EASYRSA_PKI/issued/$server_cn.crt
key $EASYRSA_PKI/private/$server_cn.key

# Diffie hellman parameters.
# Generate your own with:
#   openssl dhparam -out dh2048.pem 2048
dh $EASYRSA_PKI/dh.pem

# Configure server mode and supply a VPN subnet
# for OpenVPN to draw client addresses from.
# The server will take 10.8.0.1 for itself,
# the rest will be made available to clients.
# Each client will be able to reach the server
# on 10.8.0.1. Comment this line out if you are
# ethernet bridging. See the man page for more info.
server $server_netmask

# To assign specific IP addresses to specific
# clients or if a connecting client has a private
# subnet behind it that should also have VPN access,
# use the subdirectory 'ccd' for client-specific
# configuration files (see man page for more info).
client-config-dir $OVER_CONF_D/ccd
route $server_route
# Then create a file ccd/Thelonious with this line:
#   iroute 192.168.40.128 255.255.255.248
# This will allow Thelonious' private subnet to
# access the VPN.  This example will only work
# if you are routing, not bridging, i.e. you are
# using 'dev tun' and 'server' directives.

# If enabled, this directive will configure
# all clients to redirect their default
# network gateway through the VPN, causing
# all IP traffic such as web browsing and
# and DNS lookups to go through the VPN
# (The OpenVPN server machine may need to NAT
# or bridge the TUN/TAP interface to the internet
# in order for this to work properly).
push 'redirect-gateway def1 bypass-dhcp'

# The keepalive directive causes ping-like
# messages to be sent back and forth over
# the link so that each side knows when
# the other side has gone down.
# Ping every 10 seconds, assume that remote
# peer is down if no ping received during
# a 120 second time period.
keepalive ${server_keepalive:-10 60}

# For extra security beyond that provided
# by SSL/TLS, create an 'HMAC firewall'
# to help block DoS attacks and UDP port flooding.
#
# Generate with:
#   openvpn --genkey tls-auth ta.key
#
# The server and each client must have
# a copy of this key.
# The second parameter should be '0'
# on the server and '1' on the clients.
tls-auth $EASYRSA_PKI/ta.key
key-direction 0

# It's a good idea to reduce the OpenVPN
# daemon's privileges after initialization.
#
# You can uncomment this out on
# non-Windows systems.
user nobody
group nogroup

# The persist options will try to avoid
# accessing certain resources on restart
# that may no longer be accessible because
# of the privilege downgrade.
persist-key
persist-tun

# Output a short status file showing
# current connections, truncated
# and rewritten every minute.
status /var/log/openvpn.log

# Set the appropriate level of log
# file verbosity.
#
# 0 is silent, except for fatal errors
# 4 is reasonable for general usage
# 5 and 6 can help to debug connection problems
# 9 is extremely verbose
verb ${server_verbose:-3}

"
}

_client_conf () {
    printf "##############################################
# Sample client-side OpenVPN 2.0 config file #
# for connecting to multi-client server.     #
#                                            #
# This configuration can be used by multiple #
# clients, however each client should have   #
# its own cert and key files.                #
#                                            #
# On Windows, you might want to rename this  #
# file so it has a .ovpn extension           #
##############################################

# Specify that we are a client and that we
# will be pulling certain config file directives
# from the server.
client

# Use the same setting as you are using on
# the server.
# On most systems, the VPN will not function
# unless you partially or fully disable
# the firewall for the TUN/TAP interface.
dev tun

# Most clients don't need to bind to
# a specific local port number.
nobind

# Are we connecting to a TCP or
# UDP server?  Use the same setting as
# on the server.
proto $server_proto

# The hostname/IP and port of the server.
# You can have multiple remote entries
# to load balance between the servers.
remote $server_cn $server_port

# SSL/TLS parms.
# See the server config file for more
# description.  It's best to use
# a separate .crt/.key file pair
# for each client.  A single ca
# file can be used for all clients.
<ca>
$(cat $EASYRSA_PKI/ca.crt)
</ca>
<cert>
$(openssl x509 -in $EASYRSA_PKI/issued/$client_cn.crt)
</cert>
<key>
$(cat $EASYRSA_PKI/private/$client_cn.key)
</key>

# If a tls-auth key is used on the server
# then every client must also have the key.
<tls-auth>
$(cat $EASYRSA_PKI/ta.key)
</tls-auth>
key-direction 1

# Verify server certificate by checking that the
# certificate has the correct key usage set.
# This is an important precaution to protect against
# a potential attack discussed here:
#  http://openvpn.net/howto.html#mitm
#
# To use this feature, you will need to generate
# your server certificates with the keyUsage set to
#   digitalSignature, keyEncipherment
# and the extendedKeyUsage to
#   serverAuth
# EasyRSA can do this for you.
remote-cert-tls server

redirect-gateway def1

"

}

_usage() {
    printf "$@

usage: ${0##*/} [option]

    start  [option]             start server
    add    [name]               add new client user by name
    get    [name] > [name].ovpn print client user config by name
    list                        list all client user
    del    [name]               delete user by name

" >&2

}

_start_usage() {
	printf "$@

usage: ${0##*/} start [option]

    --common-name, -cn  Set hostname with protocol.
                        e.g.
                            10.0.0.1
    --device,      -d   [tunX|tapX]
                        tun/tap device (X can be omitted for dynamic device.
    --dns               Set DNS servers.
                        e.g.
                            8.8.8.8 4.4.4.4
    --keepalive,   -k   Helper option for setting timeouts in server mode.  Send
                        ping once every n seconds, restart if ping not received
                        for m seconds.
    --netmask           network netmask : Helper option to easily configure server mode.
                        e.g.
                            192.168.255.0/24
                            192.168.255.0 255.255.255.0
    --nopass            no password.
    --proto,       -t   [udp|tcp]
                        Use protocol p for communicating with peer, default: udp.
    --port,        -p   Listening Port, default: 1194
    --route             Add route to routing table after connection
                        is established.  Multiple routes can be specified.
                        e.g.
                            192.168.254.0/24
                            192.168.254.0 255.255.255.0
    --verbose,     -v   Set output verbosity to n (default=3):
                        (Level 3 is recommended if you want a good summary
                        of what is happening without being swamped by output).
                        0 -- no output except fatal errors
                        1 -- startup info + connection initiated messages +
                            non-fatal encryption & net errors
                        2,3 -- show TLS negotiations & route info
                        4 -- show parameters
                        5 -- show 'RrWw' chars on console for each packet sent
                        and received from TCP/UDP (caps) or tun/tap (lc)
                        6 to 11 -- debug messages of increasing verbosity

" >&2

}

_init() {

    local server_cn server_devic server_dns server_keepalive server_netmask \
        server_nopass=false server_port server_proto server_route server_verbose

    while [ "$1" ]; do
        case $1 in
            --common-name|-cn)
                $(awk -v host="$2" 'BEGIN{if ( \
                    host ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ || \
                    host ~ /^([0-9A-Fa-f]{0,4}:){1,7}[0-9A-Fa-f]{0,4}$/ || \
                    host ~ /^([0-9A-Za-z-]+\.)+[a-z]+$/ \
                ) {print "true"} else print "false"}') || {
                    _start_usage "Invalid hostname: '$2'";
                    exit 1

                };

                server_cn=$2;
                shift
            ;;
            --device|-d)
                printf "%s" $2 | grep -q '^t\(un\|ap\)[0-9]\+$' || {
                    _start_usage "Device not support: '$2'";
                    exit 1

                };
                server_device=$2;
                shift
            ;;
            --dns)
                shift;
                while [ "$1" -a "${1#-}" == "$1" ]; do
                    $(awk -v ip="$1" 'BEGIN{if(ip ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) {print "true"} else print "false"}') || {
                        _start_usage "Invalid DNS: '$1'";
                        exit 1

                    };
                    server_dns+=" $1";
                    shift
                done
                [ "$server_dns" ] || {
                    _start_usage "Empty DNS: '$1'";
                    exit 1

                };

            ;;
            --keepalive|-k)
                server_keepalive="$2 $3";
                printf "%s" "$server_keepalive" | grep -q '^[0-9]\+ [0-9]\+$' || {
                    _start_usage "Invalid keepalive: '$server_keepalive'";
                    exit 1

                };
                shift;
                shift

            ;;
            --netmask)
                if [ "$3" -a "${3#-}" == "$3" ]; then
                    server_netmask="$2 $3";
                    shift;
                else
                    server_netmask="$2";
                fi
                $(awk -v netmask="$server_netmask" 'BEGIN{if( \
                    netmask ~ /^([0-9]{1,3}\.){3}[0-9]{1,3} ([0-9]{1,3}\.){3}[0-9]{1,3}$/ || \
                    netmask ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]+$/
                ) {print "true"} else print "false"}') || {
                    _start_usage "Invalid netmask: '$server_keepalive'";
                    exit 1

                };
                shift

            ;;
            --nopass) server_nopass=true;;
            --proto|-t)
                printf "%s" $2 | grep -q '^\(ud\|tc\)p$' || {
                    _start_usage "Proto not support: '$2'";
                    exit 1

                };
                server_proto=$2;
                shift

            ;;
            --port|-p)
                $(awk -v port="$2" 'BEGIN{if(port ~ /^[1-9][0-9]{1,4}$/) {print "true"} else print "false"}') || {
                    _start_usage "Not a port: '$2'";
                    exit 1

                };
                server_port=$2;
                shift

            ;;
            --route)
                if [ "$3" -a "${3#-}" == "$3" ]; then
                    server_route="$2 $3";
                    shift

                else
                    server_route="$2";
                fi
                $(awk -v route="$server_route" 'BEGIN{if( \
                    route ~ /^([0-9]{1,3}\.){3}[0-9]{1,3} ([0-9]{1,3}\.){3}[0-9]{1,3}$/ || \
                    route ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]+$/
                ) {print "true"} else print "false"}') || {
                    _start_usage "Invalid route: '$server_route'";
                    exit 1

                };
                shift

            ;;
            --verbose|-v)
                printf "%s" $2 | grep -q '^\([0-9]\|1[0-6]\)$' || {
                    _start_usage "Invalid verbose: '$2'";
                    exit 1

                };
                server_verbose=$2;
                shift
            ;;
            *)
                _start_usage "Invalid option: '$1'";
                exit 1

            ;;
        esac
        shift
    done

    mkdir -pv $OVER_CONF_D/ccd $OVER_CONF_D/conf;

    easyrsa init-pki; # create dir, copy cnf

    # create ca
    : ${server_cn:='127.0.0.1'};
    local easyrsa_opts;
    $server_nopass && {
        easyrsa --batch --req-cn=$server_cn build-ca nopass;
        :

    } || {
        local passfile=$(mktemp -u $OVER_CONF_D/conf/XXXXXX);
        openssl rand -base64 9 > $passfile;
        easyrsa_opts="--passin=file:$passfile";
        easyrsa $easyrsa_opts --passout=file:$passfile --batch --req-cn=$server_cn build-ca

    };

    easyrsa gen-dh;
    openvpn --genkey --secret $EASYRSA_PKI/ta.key;

    # create server key
    easyrsa $easyrsa_opts build-server-full "$server_cn" nopass;

    # CRL
    easyrsa $easyrsa_opts gen-crl;

    # create server config
    : ${server_netmask:='192.168.255.0/24'};
    [ "${server_netmask/\//}" != "$server_netmask" -a "${server_netmask/ /}" == "$server_netmask" ] && \
        server_netmask=$(_CIDR_prefix2subnet_mask $server_netmask);

    : ${server_route:='192.168.254.0/24'};
    [ "${server_route/\//}" != "$server_route" -a "${server_route/ /}" == "$server_route" ] && \
        server_route=$(_CIDR_prefix2subnet_mask $server_route);

    {
        _server_conf;
        printf "
# Certain Windows-specific network settings
# can be pushed to clients, such as DNS
# or WINS server addresses.  CAVEAT:
# http://openvpn.net/faq.html#dhcpcaveats
# The addresses below refer to the public
# DNS servers provided by opendns.com.
"
        local i;
        for i in ${server_dns:-"8.8.8.8 8.8.4.4"}; do
            printf 'push "dhcp-option DNS %s"\n' $i
        done
        printf "\n"
    } > $OVER_CONF_D/conf/server.conf;

    cp -v $EASYRSA_PKI/crl.pem $OVER_CONF_D/conf && \
        chmod 644 $OVER_CONF_D/conf/crl.pem;

    $server_nopass || \
        printf "\npass phrase for $EASYRSA_PKI/private/ca.key in '%s' file.\n\n" $passfile;


}

# [O]PEN[V]PN[E]ASY[R]SA
export OVER_CONF_D=${OVER_CONF_D:-'/etc/openvpn'};
export EASYRSA=/usr/share/easy-rsa \
    EASYRSA_PKI=$OVER_CONF_D'/pki'\
    EASYRSA_REQ_COUNTRY=${OVER_REQ_COUNTRY:-'CN'} \
    EASYRSA_REQ_PROVINCE=${OVER_REQ_PROVINCE:-'BEIJING'} \
    EASYRSA_REQ_CITY=${OVER_REQ_CITY:-'BEIJING'} \
    EASYRSA_REQ_ORG=${OVER_REQ_ORG:-'Copyleft Certificate Co'} \
    EASYRSA_REQ_EMAIL=${OVER_REQ_EMAIL:-'me@example.net'} \
    EASYRSA_REQ_OU=${OVER_REQ_OU:-'My Organizational Unit'} \
    EASYRSA_CRL_DAYS=${OVER_CRL_DAYS:-3650};

export PATH=$EASYRSA:$PATH;

unset EASYRSA_VARS_FILE;

case $1 in
    start)
        ps -ef | grep -q '[[:space:]]openvpn[[:space:]]' && {
            printf "Openvpn already running.\n" >&2;
            exit 1
        };

        shift; # for _init

        # test or create
        [ -s $OVER_CONF_D/conf/server.conf ] || _init "$@";

        server_nat_device=$(route | awk '/default/{printf $8}');
        # Setup iptables and route
        awk '/^(server|route)/{print $2, $3}' $OVER_CONF_D/conf/server.conf | \
            while read CIDR; do
                iptables \
                    --table nat \
                    --check POSTROUTING \
                    --source "`_subnet_mask2CIDR_prefix $CIDR`" \
                    --out-interface $server_nat_device \
                    --jump MASQUERADE 2>/dev/null || \
                    iptables \
                        --table nat \
                        --append POSTROUTING \
                        --source "`_subnet_mask2CIDR_prefix $CIDR`" \
                        --out-interface $server_nat_device \
                        --jump MASQUERADE

            done

        [ -c /dev/net/tun ] || {
            mkdir -p /dev/net;
            mknod /dev/net/tun c 10 200

        };

        exec openvpn \
            --config $OVER_CONF_D/conf/server.conf \
            --crl-verify $OVER_CONF_D/conf/crl.pem;

    ;;
    add)
        if [ ${#2} == 0 ]; then
            _usage "Need name.";
            exit 1

        elif [ -f "$EASYRSA_PKI/issued/$2.crt" ]; then
            printf "Add faild, client config '%s' already exist.\n" $2 >&2;
            exit 1

        elif [ "${2/[^0-9A-Za-z_-]/}" != "$2" ]; then
            printf "Add faild, Invalid name '%s'\n" $2 >&2;
            exit 1

        fi

        easyrsa build-client-full $2 nopass || \
            rm -f \
            "$EASYRSA_PKI/private/$2.key" \
            "$EASYRSA_PKI/reqs/$2.req"

    ;;
    list)
        server_crt_name=$(awk '/^cert/{sub(/.*\//, ""); sub(/.crt/, ""); print}' $OVER_CONF_D/conf/server.conf);
        for name in "$EASYRSA_PKI"/issued/*.crt; do
            name=${name%.*};
            [ "$server_crt_name" == "${name##*/}" ] && continue;
            ls -lc --full-time $name.crt | awk -v name=${name##*/} '{printf "%-16s %s %s\n", name, $6, $7}'

        done

    ;;
    del|get)
        if [ ${#2} == 0 ]; then
            _usage "Need name.";
            exit 1

        elif [ ! -f "$EASYRSA_PKI/issued/$2.crt" ]; then
            printf "Client config '%s' not exist.\n" $2 >&2;
            exit 1

        elif [ "${2/[^0-9A-Za-z_-]/}" != "$2" ]; then
            printf "Invalid name '%s'\n" $2 >&2;
            exit 1

        elif [ "$(awk '/^cert/{sub(/.*\//, ""); print}' $OVER_CONF_D/conf/server.conf)" == "$2.crt" ]; then
            printf "Operation not permitted.\n" $2 >&2;
            exit 1

        fi

        export client_cn="$2";
        if [ "$1" == "del" ]; then
            passfile=$(mktemp -u /dev/shm/XXXXXX)$RANDOM;
            printf "Enter pass phrase:"
            read -r -s;
            printf "\n";
            printf "%s" "$REPLY" > $passfile;
            unset REPLY;
            easyrsa --passin=file:$passfile revoke "$client_cn" || {
                rm -f $passfile;
                exit 1

            };
            easyrsa --passin=file:$passfile gen-crl && \
                cp -f $EASYRSA_PKI/crl.pem $OVER_CONF_D/conf && \
                chmod 644 $OVER_CONF_D/conf/crl.pem;
            rm -f $passfile \
                "$EASYRSA_PKI/issued/$client_cn.crt" \
                "$EASYRSA_PKI/private/$client_cn.key" \
                "$EASYRSA_PKI/reqs/$client_cn.req"

        else
            export \
                server_proto=$(awk '/^proto[[:space:]]+/{print $2}' $OVER_CONF_D/conf/server.conf) \
                server_port=$(awk '/^port[[:space:]]+/{print $2}' $OVER_CONF_D/conf/server.conf) \
                server_cn=$(awk '/^cert/{sub(/.*\//, ""); sub(/.crt/, ""); print}' $OVER_CONF_D/conf/server.conf);

            _client_conf

        fi

    ;;
    *)
        _usage "Invalid option: '$1'"

    ;;
esac
