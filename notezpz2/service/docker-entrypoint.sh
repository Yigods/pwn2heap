#!/bin/sh
# Based on CTF-Archives/ctf-docker-template dynamic flag entrypoint.
set -eu

user="ctf"

if [ "${DASFLAG:-}" ]; then
    INSERT_FLAG="$DASFLAG"
    export DASFLAG=no_FLAG
    DASFLAG=no_FLAG
elif [ "${FLAG:-}" ]; then
    INSERT_FLAG="$FLAG"
    export FLAG=no_FLAG
    FLAG=no_FLAG
elif [ "${GZCTF_FLAG:-}" ]; then
    INSERT_FLAG="$GZCTF_FLAG"
    export GZCTF_FLAG=no_FLAG
    GZCTF_FLAG=no_FLAG
else
    INSERT_FLAG="flag{TEST_Dynamic_FLAG}"
fi

# In the xinetd chroot, /home/ctf/flag is seen by the challenge as /flag.
printf '%s
' "$INSERT_FLAG" > "/home/$user/flag"
chmod 744 "/home/$user/flag"
chown root:ctf "/home/$user/flag"

# Do not keep the real flag in exported environment for children.
unset INSERT_FLAG

chmod 711 /home/ctf/attachment
/etc/init.d/xinetd start
sleep infinity
