
			    Simple Repeater

			   stone version 2.3e

		Copyright(c)1995-2008 by Hiroaki Sengoku
			    sengoku@gcd.org


  Stone is a TCP/IP repeater in the application layer.  It repeats TCP
and UDP from inside to outside of a firewall, or from outside to inside.

  Stone has following features:

1.  Stone supports Win32.
	Formerly, UNIX machines are used as firewalls, but recently
	WindowsNT machines are used, too.  You can easily run stone on
	WindowsNT and Windows95.  Of course, available on Linux,
	FreeBSD, BSD/OS, SunOS, Solaris, HP-UX and so on.

2.  Simple.
	Stone's source code is only 10000 lines long (written in C
	language), so you can minimize the risk of security
	holes.

3.  Stone supports SSL.
	Using OpenSSL (http://www.openssl.org/), stone can
	encrypt/decrypt.  Client verifications, and server verifications
	are also supported.  Stone can send a substring of the subject
	of the certificate to the destination.

4.  Stone is a http proxy.
	Stone can also be a tiny http proxy.

5.  POP -> APOP conversion.
	With stone and a mailer that does not support APOP, you can
	access to an APOP server.

6.  Stone supports IPv6.
	Stone can convert IP and IPv6 each other.  With stone, you can
	use IP-only software on IPv6 network.


HOWTO USE

	stone [-C <file>] [-P <command>] [-Q <options>] [-N] [-d] [-p] [-n]
	      [-u <max>] [-f <n>] [-l] [-L <file>] [-a <file>] [-i <file>]
	      [-X <n>] [-T <n>] [-A <n>] [-r]
	      [-x <port>[,<port>][-<port>]... <xhost>... --]
	      [-s <send> <expect>... --]
	      [-b [<var>=<val>]... <n> <master>:<port> <backup>:<port>]
	      [-B <host>:<port> <host1>:<port1>... --]
	      [-I <host>]
	      [-o <n>] [-g <n>] [-t <dir>] [-D] [-c <dir>]
	      [-q <SSL>] [-z <SSL>]
	      [-M install <name>] [-M remove <name>]
	      <st> [-- <st>]...

	If the ``-C <file>'' flag is used, the program read these
	options and ``<st>''s from the configuration file ``<file>''.
	If the ``-P <command>'' flag is used, the program executes
	pre-processor to read the configuration file.  ``-Q <options>''
	can be used to pass options to the pre-processor.  If the ``-N''
	flag is used, stone will terminate after parsing options without
	opening the ports.

	If the ``-d'' flag is used, then increase the debug level.  If
	the ``-p'' flag is used, data repeated by stone are dumped.  If
	the ``-n'' is used, IP addresses and service port numbers are
	shown instead of host names and service names.

	If the ``-u <max>'' flag (``<max>'' is integer) is used, the
	program memorize ``<max>'' UDP sources simultaneously.  The
	default value is 100.  If the ``-f <n>'' flag (``<n>'' is
	integer) is used, the program spawn ``<n>'' child processes.
	The default behavior is not to spawn any child processes.

	If the ``-l'' flag is used, the program sends error messages to
	the syslog instead of stderr.  If the ``-L <file>'' (``<file>''
	is a file name) flag is used, the program writes error messages
	to the file.  If the ``-a <file>'' flag is used, the program
	writes accounting to the file.  If the ``-i <file>'' flag is
	used, the program writes its process ID to the file.

	The ``-X <n>'' flag alters the buffer size of the repeater.  The
	default value is 1000 bytes.  If the ``-T <n>'' is used, the
	timeout of TCP sessions can be specified to ``<n>'' sec.
	Default: 600.  The ``-A'' flag specifies the maximum length the
	queue of pending connections may grow to.  Default: 50.  The
	``-r'' flag is used, SO_REUSEADDR is set on the socket of <st> .

	Using the ``-x <port>[,<port>][-<port>]... <xhost>... --'' flag,
	the http proxy (described later) can only connect to
	<xhost>:<port>.  If more than one ``-x ... --'' flags are
	designated, the posterior one whose <port> list matches the
	connecting port.  If the ``-x --'' is used, prior ``-x'' flags
	are ignored.

	The ``-b <n> <master>:<port> <backup>:<port>'' flag designates
	the backup destination for <master>:<port>.  The program checks
	every <n> seconds whether <master>:<port> is connectable, using
	the health check script defined by ``-s'' flag described below.
	If not, the backup is used instead.  Alternative <host> can be
	checked, using ``host=<host>'' and alternative <port>, using
	``port=<port>''.

	The ``-s <send> <expect>... --'' flag defines the health check
	script.  Sending <send>, then checks whether the response match
	the regular expression <expect>.

	The ``-B <host>:<port> <host1>:<port1>... --'' is for the
	destination group.  If the destination of <st> is <host>:<port>,
	the program chooses a destination randomly from the group.  The
	destination <host>:<port> that is designated by ``-b'' flag and
	turned out unhealthy, is excluded from the group.

	The ``-I <host>'' designates the interface used as the source
	address of the connection to the desctination.

	If the ``-o <n>'' or ``-g <n>'' flag is used, the program set
	its uid or gid to ``<n>'' respectively.  If the ``-t <dir>''
	flag (``<dir>'' is a directory) is used, the program change its
	root to the directory.  If the ``-D'' flag is used, stone runs
	as a daemon.  The ``-c <dir>'' flag designates the directory for
	core dump.

	The ``-M install <name>'' and the ``-M remove <name>'' flags are
	for NT service.  ``<name>'' is the service name.  Start the
	service using the command: net start <name>.  To install stone
	service as the name ``repeater'', for example:

		C:\>stone -M install repeater -C C:\stone.cfg
		C:\>net start repeater

	The ``-q <SSL>'' and the ``-z <SSL>'' flags are for SSL
	encryption.  The ``-q <SSL>'' is for the client mode, that is,
	when stone connects to the other SSL server as a SSL client.
	The ``-z <SSL>'' if for the server mode, that is, when other SSL
	clients connect to the stone.

	``<SSL>'' is one of the following.

	default		reset SSL options to the default.
			Using multiple <st>, different SSL options can
			be designated for each <st>.
	verbose		verbose mode.
	verify		require SSL certificate to the peer.
	verify,once	request a client certificate on the initial TLS/SSL
			handshake. (-z only)
	verify,ifany	The certificate returned (if any) is checked. (-z only)
	verify,none	never request SSL certificate to the peer.
	crl_check	lookup CRLs.
	crl_check_all	lookup CRLs for whole chain.
	uniq		if the serial number of peer's SSL certificate
			is different from the previous session, deny it.
	re<n>=<regex>	The certificate of the peer must satisfy the
			<regex>.  <n> is the depth.  re0 means the subject
			of the certificate, and re1 means the issure.
			The maximum of <n> is 9.
			if <n> is negative, re-1 means the root CA and
			re-2 means its child CA.
	depth=<n>	The maximum of the certificate chain.
			If the peer's certificate exceeds <n>, the
			verification fails.  The maximum of <n> is 9.
	tls1		Just use TLSv1 protocol.
	ssl3		Just use SSLv3 protocol.
	ssl2		Just use SSLv2 protocol.
	no_tls1		Turn off TLSv1 protocol.
	no_ssl3		Turn off SSLv3 protocol.
	no_ssl2		Turn off SSLv2 protocol.
	sni		Server Name Indication (SNI).
	servername=<str>	The name of the server indicated by SNI.
	bugs		Switch on all SSL implementation bug workarounds.
	serverpref	Use server's cipher preferences (only SSLv2).
	sid_ctx=<str>	Set session ID context.
	passfile=<file>	The filename of the file containing password of the key
	passfilepat=<file>	The pattern of the filename
	key=<file>	The filename of the secret key of the certificate.
	keypat=<file>		The pattern of the filename
	cert=<file>	The filename of the certificate.
	certpat=<file>		The pattern of the filename
	certkey=<file>	The filename of the certificate with the secret key.
	certkeypat=<file>	The pattern of the filename
	CAfile=<file>	The filename of the certificate of the CA.
	CApath=<dir>	The directory of the certificate files.
	pfx=<file>	The filename of the PKCS#12 bag.
	pfxpat=<file>		The pattern of the filename
	store=<prop>	[Windows] Use the secret key in the Cert Store.
			designate by "SUBJ:<substr>" or "THUMB:<hex>"
	storeCA		[Windows] Use CA certificates in the Cert Store.
	cipher=<list>	The list of ciphers.
	lb<n>=<m>	change the destination according to the
			certificate of the peer.  The number calculated
			from the matched string to the <n>th ( ... ) in
			the ``regex'' of SSL options (mod <m>) is used
			to select the destination from the destination
			group defined by ``-B'' flag.

	``<st>'' is one of the following.  Multiple ``<st>'' can be
	designated, separated by ``--''.

	(1)	<host>:<port> <sport> [<xhost>...]
	(2)	<host>:<port> <shost>:<sport> [<xhost>...]
	(3)	proxy <sport> [<xhost>...]
	(4)	<host>:<port>/http <sport> <request> [<xhost>...]
	(5)	<host>:<port>/proxy <sport> <header> [<xhost>...]
	(6)	health <sport> [<xhost>...]

	The program repeats the connection on port ``<sport>'' to the
	other machine ``<host>'' port ``<port>''.  If the machine, on
	which the program runs, has two or more interfaces, type (2) can
	be used to repeat the connection on the specified interface
	``<shost>''.  You can also specify path name that begins with
	``/'' or ``./'', instead of ``<host>:<port>'' so that the
	program handles a unix domain socket.

	Type (3) is a http proxy.  Specify the machine, on which the
	program runs, and port ``<sport>'' in the http proxy settings of
	your WWW browser.
	Extentions can be added to the ``proxy'' like ``<xhost>/<ext>''.
	<ext> is:

	v4only	limit the destination within IP addresses.

	v6only	limit the destination within IPv6 addresses.

	Type (4) relays stream over http request.  ``<request>'' is the
	request specified in HTTP 1.0.  In the ``<request>'', ``\'' is
	the escape character, and the following substitution occurs.

		\n	newline  (0x0A)
		\r	return   (0x0D)
		\t	tab      (0x09)
		\\	\ itself (0x5C)
		\a	the IP address of the client connecting to the stone.
		\A	<IP address of the client>:<port number>
		\d	the destination IP address
		\D	<dst IP address>:<port number> (for transparent proxy)
		\u	uid (number) of the client
		\U	user name of the client
		\g	gid (number) of the client
		\G	group name of the client
			\u \U \g \G are valid in the case of unix domain socket
		\0	the serial number of peer's SSL certificate.
		\1 - \9	the matched string in the ``regex'' of SSL options.
		\?1<then>\:<else>\/
			if \1 (\2 - \9 in a similar way) is not null,
			<then>, otherwise <else>.

	Type (5) repeats http request with ``<header>'' in the top of
	request headers.  The above escapes can be also used.  If
	``/mproxy'' is designated instead of ``/proxy'', ``<header>'' is
	added to each request headers.

	Type (6) designates the port that other programs can check
	whether the stone runs `healthy' or not.  Following commands are
	available to check the stone.

		HELO <any string>	returns the status of the stone
		STAT			# of threads, mutex conflicts
		FREE			length of free lists
		CLOCK			seconds passed
		CVS_ID			CVS ID
		CONFIG			content of the configuration file
		STONE			configuration of each stones
		LIMIT <var> <n>		check the value of <var> is
					less than <n>
	``<var>'' is one of the following:

		PAIR		the number of ``pair''
		CONN		the number of ``conn''
		ESTABLISHED	seconds passed since the last conn established
		READWRITE	seconds passed since the last read/write
		ASYNC		the number of threads

	The response of the stone is 2xx when normal, or 5xx when
	abnormal on the top of line.

	If the ``<xhost>'' are used, only machines or its IP addresses
	listed in ``<xhost>'' separated by space character can
	connect to the program and to be repeated.

	Extentions can be added to the ``<xhost>'' like
	``<xhost>/<ex>,<ex>...''.  <ex> is:

	<m>	You can designate the length of prefix bits of the
		netmask, so that only machines on specified.  In the
		case of class C network 192.168.1.0, for example, use
		``192.168.1.0/24''.

	v4	<xhost> is resolved as the IP address.

	v6	<xhost> is resolved as the IPv6 address.

	p<m>	the data repeated by the program are dumped, only if it
		was connected by the machines specified by <xhost>.  <m>
		is the dump mode, equivalent to the number of ``-p''
		options.

	Use ``!'' instead of ``<xhost>'', to deny machines by following
	``<xhost>''.

	Extentions can be added to the ``<port>'' like
	``<port>/<ext>,<ext>...''.  <ext> is:

	udp	repeats UDP instead of TCP.

	ssl	forwards with encryption.

	v6	connects to the destination using IPv6.

	base	forwards with MIME base64 encoding.

	Extentions can be added to the ``<sport>'' like
	``<sport>/<ext>,<ext>...''.  <ext> is:

	udp	repeats UDP instead of TCP.

	apop	converts POP to APOP.  The conversion is derived from
		the RSA Data Security, Inc. MD5 Message-Digest Algorithm.

	ssl	forwards with decryption.

	v6	accepts connection using IPv6.  If <shost> is omitted 
		like (1), IP is also acceptable.

	v6only	accepts connection using IPv6 only.  Even if <shost> is
		omitted like (1), IP is not acceptable.

	base	forwards with MIME base64 decoding.

	http	relays stream over http.

	ident	identifies the owner of the incoming connection
		on the peer using ident protocol (RFC1413).


EXAMPLES
	outer: a machine in the outside of the firewall
	inner: a machine in the inside of the firewall
	fwall: the firewall on which the stone is executed

	stone outer:telnet 10023
		Repeats the telnet protocol to ``outer''.
		Run ``telnet fwall 10023'' on ``inner''.

	stone outer:domain/udp domain/udp
		Repeats the DNS query to ``outer''.
		Run ``nslookup - fwall'' on ``inner''.

	stone outer:ntp/udp ntp/udp
		Repeats the NTP to ``outer''.
		Run ``ntpdate fwall'' on ``inner''.

	stone localhost:http 443/ssl
		Make WWW server that supports ``https''.
		Access ``https://fwall/'' using a WWW browser.

	stone localhost:telnet 10023/ssl
		Make telnet server that supports SSL.
		Run ``SSLtelnet -z ssl fwall 10023'' on ``inner''.

	stone proxy 8080
		http proxy.

	stone outer:110/apop 110
		connect to inner:pop using a mailer that does not
		support APOP.

	Where fwall is a http proxy (port 8080):

	stone fwall:8080/http 10023 'POST http://outer:8023 HTTP/1.0'
	stone localhost:telnet 8023/http
		Run stones on ``inner'' and ``outer'' respectively.
		Relays stream over http.

	stone fwall:8080/proxy 9080 'Proxy-Authorization: Basic c2VuZ29rdTpoaXJvYWtp'
		for browser that does not support proxy authorization.


HOMEPAGE

	The official homepage of stone is:
	http://www.gcd.org/sengoku/stone/


COPYRIGHT

	All rights about this program ``stone'' are reserved by the
	original author, Hiroaki Sengoku.  The program is free software;
	you can redistribute it and/or modify it under the terms of the
	GNU General Public License (GPL).  Furthermore you can link it
	with openssl.


NO WARRANTY

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY.


#2939
http://www.gcd.org/sengoku/		Hiroaki Sengoku <sengoku@gcd.org>
