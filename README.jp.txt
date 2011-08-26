
			    Simple Repeater

			   stone version 2.3e

		Copyright(c)1995-2008 by Hiroaki Sengoku
			    sengoku@gcd.org


  stone は、アプリケーションレベルの TCP & UDP リピーターです。ファイア
ウォールの内から外へ、あるいは外から内へ、TCP あるいは UDP を中継します。

  stone には以下のような特徴があります。

1. Win32 に対応している
	以前は UNIX マシンで構成されることが多かったファイアウォールです
	が、最近は WindowsNT が使われるケースが増えてきました。stone は 
	WindowsNT あるいは Windows95 上で手軽に実行することができます。
	もちろん、Linux, FreeBSD, BSD/OS, SunOS, Solaris, HP-UX などの 
	UNIX マシンでも使うことができます。

2. 単純
	わずか 10000 行 (C 言語) ですので、セキュリティホールが生じる可能
	性を最小限にできます。

3. SSL 対応
	OpenSSL (http://www.openssl.org/) を使うことにより、暗号化/復号
	して中継できます。また、クライアント認証およびサーバ認証をサポー
	トしています。さらに、認証によって得られる証明書のサブジェクトの
	一部を、中継先へ送ることもできます。

4. http proxy
	簡易型 http proxy としても使うことができます。

5. POP -> APOP 変換
	APOP に対応していないメーラと stone を使うことで、APOP サーバへ
	アクセスできます。

6. IPv6 対応
	IP/IPv6 変換して中継することができます。IPv6 に対応していない
	ソフトウェアを手軽に IPv6 化することが可能です。


使用方法

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

	-C はオプションおよび <st> をコマンドラインで指定するかわりに設
	定ファイルから読み込みます。-P は設定ファイルを読み込む際のプリ
	プロセッサを指定します。プリプロセッサへ与える引数は -Q で指定で
	きます。-N を指定すると、コマンドラインおよび設定ファイルを読み
	込んだ後、終了します。つまりポートを開くこと無く設定ファイルの
	チェックを行なうことができます。

	オプションとして -d を指定すると、デバッグレベルを増加させます。 
	-p を指定すると中継したデータをダンプします。-n を指定すると、ホ
	スト名やサービス名の代わりに IP アドレスやサービス番号を表示しま
	す。

	-u オプションは同時に記憶できる UDP の発信元の最大数を指定します。
	デフォルトは 100 です。-f オプションは子プロセスの数を指定します。
	デフォルトは子プロセス無しです。

	-l を指定すると、エラーメッセージ等を syslog へ出力します。-L を
	指定すると、エラーメッセージ等を file へ出力します。-a を指定す
	ると、アクセスログを file へ出力します。-i は stone のプロセス 
	ID を出力するファイルを指定します。

	-X は中継を行なう際のバッファの大きさを指定します。デフォルトは
	1000 バイトです。-T を指定すると TCP セッションのタイムアウトの秒
	数を変更できます。デフォルトは 600 (10 分) です。-A を指定すると
	listen 呼び出しの未処理接続キューの最大長を変更できます。デフォル
	トは 50 です。-r を指定すると <st> のソケットに SO_REUSEADDR を設
	定します。

	-x を指定すると http proxy の接続先を制限できます。接続先のポー
	ト番号のリスト <port>[,<port>][-<port>]... および接続先ホストの
	リスト <xhost>... を指定します。-x を複数指定すると、最後に指定
	したものから順に、ポート番号のリストがマッチするものを検索します。
	-x -- を指定すると、それ以前のものは検索対象となりません。

	-b は中継先 <master>:<port> に接続できないときのバックアップとし
	て <backup>:<port> を指定します。すなわち <n> 秒ごとに 
	<master>:<port> に対するヘルスチェック (後述する -s オプションで
	設定) が成功するかチェックし、もしチェックに失敗した場合は、中継
	先を <backup>:<port> へ変更します。<var> として「host」を指定す
	ることにより、<master> とは異なるホストをチェックすることができ
	ます。同様に、<var> として「port」を指定することにより、異なるポー
	トをチェックすることができます。

	-s はヘルスチェックのスクリプトを設定します。<send> を送信後、レ
	スポンスが、正規表現 <expect> にマッチするか確認します。

	-B は中継先グループの指定です。中継先が <host>:<port> である場合、
	このグループの中からランダムに一つの中継先を選んで中継します。-b 
	オプションで設定済みの中継先で、ヘルスチェックに失敗したものは、
	選択枝から除外します。

	-I は中継先へ接続する際に用いるインタフェースを指定します。

	-o と -g はそれぞれユーザ ID とグループ ID を指定します。ID は数
	字のみ指定可能です。-t を指定すると、dir へ chroot します。-D を
	指定すると、stone をデーモンとして起動します。-c はコアダンプを
	行なうディレクトリを指定します。

	-M は stone を NT サービスとして登録/削除するためのオプションで
	す。サービス名 <name> を指定します。サービスとして登録した後、
	net start <name> コマンドを実行してサービスを開始させてください。
	例:
		C:\>stone -M install repeater -C C:\stone.cfg
		C:\>net start repeater

	-q および -z は、SSL 暗号化/復号 のオプションです。-q は、stone 
	が SSL クライアントとして、他の SSL サーバへ接続するとき、すなわ
	ち中継先が SSL サーバの時の、SSL オプションです。-z は stone が 
	SSL サーバとして、他の SSL クライアントからの接続を受付ける時の、
	SSL オプションです。

	<SSL> は SSL オプションで、次のいずれかです。

	default		SSL オプション指定をデフォルトに戻します。
			複数の <st> を指定する際、<st> 毎に異なる SSL オ
			プションを指定することができます。
	verbose		デバッグ用文字列をログに出力します。
	verify		SSL 接続相手に、SSL 証明書を要求します。
	verify,once	セッション開始時に一度だけ、
			SSL クライアントに証明書を要求します。(-z 専用)
	verify,ifany	SSL クライアントから証明書が送られてきたときのみ
			認証します。送られてこない場合は認証せずに
			セッションを開始します。(-z 専用)
	verify,none	SSL 接続相手に SSL 証明書を要求しません。
	crl_check	CRL をチェックします。
	crl_check_all	証明書チェーンの全てにおいて CRL をチェックします。
	uniq		SSL 接続相手の SSL 証明書のシリアル番号が前回の
			接続と異なる場合、接続を拒否します。
	re<n>=<regex>	SSL 証明書のチェーンが満たすべき正規表現を指定します。
			<n> は depth です。re0 が証明書のサブジェクト、
			re1 がその発行者を意味します。
			<n> は 9 まで指定できます。
			<n> が負の値の場合は、re-1 が root CA で、
			re-2 がその子 CA を意味します。
	depth=<n>	SSL 証明書チェーンの長さの最大値を指定します。
			チェーンの長さがこの値を越えると認証が失敗します。
			<n> の最大値は 9 です。
	tls1		プロトコルとして TLSv1 を用います。
	ssl3		プロトコルとして SSLv3 を用います。
	ssl2		プロトコルとして SSLv2 を用います。
	no_tls1		プロトコルの選択枝から TLSv1 を外します。
	no_ssl3		プロトコルの選択枝から SSLv3 を外します。
	no_ssl2		プロトコルの選択枝から SSLv2 を外します。
	sni		サーバ名通知 (Server Name Indication) を行ないます。
	servername=<str>	SNI で通知するサーバ名を指定します。
	bugs		SSL の実装にバグがある接続相手との接続を可能にします。
	serverpref	SSL サーバの指定した暗号を用います (SSLv2 のみ)。
	sid_ctx=<str>	SSL セッション ID コンテキストを設定します。
	passfile=<file>	秘密鍵のパスフレーズを格納したファイルを指定します。
	passfilepat=<file>	ファイル名のパターンを指定します。
	key=<file>	証明書の秘密鍵ファイルを指定します。
	keypat=<file>		ファイル名のパターンを指定します。
	cert=<file>	証明書ファイルを指定します。
	certpat=<file>		ファイル名のパターンを指定します。
	certkey=<file>	秘密鍵付証明書ファイルを指定します。
	certkeypat=<file>	ファイル名のパターンを指定します。
	CAfile=<file>	認証局の証明書ファイルを指定します。
	CApath=<dir>	認証局の証明書があるディレクトリを指定します。
	pfx=<file>	PKCS#12 ファイルを指定します。
	pfxpat=<file>		ファイル名のパターンを指定します。
	store=<prop>	[Windows] 証明書ストア内の秘密鍵付証明書を指定。
			"SUBJ:<substr>" あるいは "THUMB:<hex>"
	storeCA		[Windows] 証明書ストア内の認証局証明書を使用します。
	cipher=<list>	暗号化アルゴリズムのリストを指定します。
	lb<n>=<m>	SSL 証明書の CN に応じて中継先を切り替えます。
			SSL オプションの re<n>= で指定した正規表現中、
			<n> 番目の ( ... ) 内の正規表現にマッチした文字
			列から算出した数値の剰余 <m> に基づいて、-B オプ
			ションで指定した中継先グループの中から中継先を選
			びます。

	<st> は次のいずれかです。<st> は「--」で区切ることにより、複数個
	指定できます。

	(1)	<host>:<port> <sport> [<xhost>...]
	(2)	<host>:<port> <shost>:<sport> [<xhost>...]
	(3)	proxy <sport> [<xhost>...]
	(4)	<host>:<port>/http <sport> <request> [<xhost>...]
	(5)	<host>:<port>/proxy <sport> <header> [<xhost>...]
	(6)	health <sport> [<xhost>...]

	stone を実行しているマシンのポート <sport> への接続を、他のマシ
	ン <host> のポート <port> へ中継します。インタフェースを複数持つ
	マシンでは、(2) のようにインタフェースのアドレス <shost> を指定
	することにより、特定のインタフェースへの接続のみを転送することが
	できます。<host>:<port> の代わりに、「/」ないし「./」から始まる
	パス名を指定することにより、UNIX ドメインソケットを扱うこともで
	きます。

	(3) は、http proxy です。WWW ブラウザの http proxy の設定で、
	stone を実行しているマシンおよびポート <sport> を指定します。
	「proxy」には、「/」に続けて以下の拡張子を付けることができます。

	v4only	proxy の接続先を IP アドレスに限定します。

	v6only	proxy の接続先を IPv6 アドレスに限定します。

	(4) は、http リクエストにのせて中継します。<request> は HTTP 1.0 
	で規定されるリクエストです。リクエスト文字列中、「\」はエスケー
	プ文字であり、次のような置き換えが行なわれます。

		\n	改行 (0x0A)
		\r	復帰 (0x0D)
		\t	タブ (0x09)
		\\	\    (0x5C)
		\a	接続元の IP アドレス
		\A	「接続元の IP アドレス」:「ポート番号」
		\d	接続先の IP アドレス
		\D	「接続先の IP アドレス」:「ポート番号」(透過プロキシ用)
		\u	接続元のユーザID (番号)
		\U	接続元のユーザ名
		\g	接続元のグループID (番号)
		\G	接続元のグループ名
			\u \U \g \G は UNIX ドメインソケットの場合のみ
		\0	SSL 証明書のシリアル番号
		\1 - \9	SSL オプションの re<n>= で指定した正規表現中、
			( ... ) 内の正規表現にマッチした文字列
		\?1<then>\:<else>\/
			もし \1 (\2 - \9 も同様) の文字列が、空文字列で
			なければ <then>、空文字列であれば <else>

	(5) は、http リクエストヘッダの先頭に <header> を追加して中継し
	ます。(4) と同様のエスケープを使うことができます。「/proxy」の代
	わりに「/mproxy」を指定すると、リクエストヘッダごとに <header> 
	を追加します。

	(6) は、stone が正常に動作しているか検査するためのポートの指定で
	す。<sport> で指定したポートに接続して以下のコマンドを送信すると、
	stone の状態が返されます。

		HELO 任意の文字列	stone, pair, trash 等の個数
		STAT			スレッドの個数, mutex コンフリクト回数
		FREE			free リスト長
		CLOCK			経過秒数
		CVS_ID			CVS の ID
		CONFIG			config ファイルの内容
		STONE			各 stone の設定内容
		LIMIT <var> <n>		変数 <var> の値が <n> 未満か調べる

	<var> は次のうちのいずれかです。

		PAIR		pair の個数
		CONN		conn の個数
		ESTABLISHED	最後に接続確立してからの秒数
		READWRITE	最後に read or write してからの秒数
		ASYNC		スレッドの本数

	stone からの応答は、正常時は 200 番台、異常時は 500 番台の数値が
	先頭につきます。

	<xhost> を列挙することにより、stone へ接続可能なマシンを制限する
	ことができます。マシン名、あるいはその IP アドレスを空白で区切っ
	て指定すると、そのマシンからの接続のみを中継します。

	<xhost> には、「/」に続けて以下の拡張子を付けることができます。
	複数の拡張子を指定するときは「,」で区切ります。

	<m>	ネットワーク・マスクのビット数を指定することにより、特定
		のネットワークのマシンからの接続を許可することができます。
		例えば、クラス C のネットワーク 192.168.1.0 の場合は、
		「192.168.1.0/24」と指定します。

	v4	<xhost> を IP アドレスとして扱います。

	v6	<xhost> を IPv6 アドレスとして扱います。

	p<m>	<xhost> からの接続のみ、中継したデータをダンプします。
		<m> はダンプ方法の指定です。-p オプションの個数に相当し
		ます。

	<xhost> の代わりに「!」を指定すると、後続の <xhost> は接続を拒否
	するマシンの指定になります。

	<port> には、「/」に続けて以下の拡張子を付けることができます。
	複数の拡張子を指定するときは「,」で区切ります。

	udp	TCP を中継する代わりに、UDP を中継します。

	ssl	SSL で暗号化して中継します。

	v6	中継先へ IPv6 接続します。

	base	MIME base64 で符号化して中継します。

	<sport> には、「/」に続けて以下の拡張子を付けることができます。
	複数の拡張子を指定するときは「,」で区切ります。

	udp	TCP を中継する代わりに、UDP を中継します。

	apop	POP を APOP へ変換して中継します。
		変換には RSA Data Security 社の MD5 Message-Digest アル
		ゴリズムを使用します。

	ssl	SSL を復号して中継します。

	v6	IPv6 接続を受付けます。(1) のようにインタフェースの
		アドレス <shost> を指定しない場合は、IP 接続も受付けるこ
		とができます。

	v6only	IPv6 接続のみを受付けます。(1) のようにインタフェースの
		アドレス <shost> を指定しない場合も、IP 接続を受付けるこ
		とはありません。

	base	MIME base64 を復号して中継します。

	http	http リクエストヘッダを取り除いて中継します。

	ident	接続を受付けるときに接続元に対し ident プロトコル 
		(RFC1413) を使ってユーザ名を照会します。


例
	outer: ファイアウォールの外側にあるマシン
	inner: ファイアウォールの内側にあるマシン
	fwall: ファイアウォール. このマシン上で stone を実行

	stone outer:telnet 10023
		outer へ telnet プロトコルを中継
		inner で telnet fwall 10023 を実行

	stone outer:domain/udp domain/udp
		DNS 問い合わせを outer へ中継
		inner で nslookup - fwall を実行

	stone outer:ntp/udp ntp/udp
		outer へ NTP を中継
		inner で ntpdate fwall を実行

	stone localhost:http 443/ssl
		WWW サーバを https 対応にする
		WWW ブラウザで https://fwall/ をアクセス

	stone localhost:telnet 10023/ssl
		telnet を SSL 化
		inner で SSLtelnet -z ssl fwall 10023 を実行

	stone proxy 8080
		http proxy

	stone outer:110/apop 110
		APOP に対応していないメーラで inner:pop へ接続

	fwall が http proxy (port 8080) である時:

	stone fwall:8080/http 10023 'POST http://outer:8023 HTTP/1.0'
	stone localhost:telnet 8023/http
		inner と outer でそれぞれ stone を実行
		http リクエストにのせて中継

	stone fwall:8080/proxy 9080 'Proxy-Authorization: Basic c2VuZ29rdTpoaXJvYWtp'
		proxy 認証に対応していないブラウザ用


ホームページ

	stone の公式ホームページは次の URL です。
	http://www.gcd.org/sengoku/stone/Welcome.ja.html


著作権

	この stone に関する全ての著作権は、原著作者である仙石浩明が所有
	します。この stone は、GNU General Public License (GPL) に準ずる
	フリーソフトウェアです。個人的に使用する場合は、改変・複製に制限
	はありません。配布する場合は GPL に従って下さい。また、openssl 
	とリンクして使用することを許可します。


無保証

	この stone は無保証です。この stone を使って生じたいかなる損害に
	対しても、原著作者は責任を負いません。詳しくは GPL を参照して下
	さい。


#2939								仙石 浩明
http://www.gcd.org/sengoku/		Hiroaki Sengoku <sengoku@gcd.org>
