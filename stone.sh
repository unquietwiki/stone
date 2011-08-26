#!/bin/sh
. /etc/rc.d/init.d/functions

start() {
    echo -n "Starting stone: "
    /usr/local/sbin/stone -C /etc/rc.d/stone
    RETVAL=$?
    if [ $RETVAL -eq 0 ]; then
	touch /var/lock/subsys/stone && success $"stone startup"
    else
	failure $"stone startup"
    fi
    echo
}

stop() {
    echo -n "Stopping stone: "
    killproc stone
    RETVAL=$?
    echo
    rm -f /var/lock/subsys/stone
}

case "$1" in
    start)	start	;;
    stop)	stop	;;
    restart)	stop
		start	;;
    *)
	echo "Usage: stone {start|stop|restart}"
	exit 1
esac
exit $RETVAL
