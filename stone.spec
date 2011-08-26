Summary: Simple Repeater
Name: stone
Version: 2.1x
Release: 1
URL: http://www.gcd.org/sengoku/stone/
Source0: %{name}-%{version}.tar.gz
License: GPL
Group: network
BuildRoot: %{_tmppath}/%{name}-root

%description
  Stone is a TCP/IP repeater in the application layer.  It
repeats TCP and UDP from inside to outside of a firewall, or
from outside to inside.

%prep
%setup -q

%build
make linux-ssl SSL_FLAGS='-DUSE_SSL' SSL_LIBS='-lssl -lcrypto'

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/{bin,share/man/{,ja/}man1}
install stone $RPM_BUILD_ROOT/usr/bin/
install -m 644 stone.1 $RPM_BUILD_ROOT/usr/share/man/man1/
install -m 644 stone.1.ja $RPM_BUILD_ROOT/usr/share/man/ja/man1/stone.1

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/usr/bin/stone
/usr/share/man/man1/stone.1.gz
/usr/share/man/ja/man1/stone.1.gz
%doc GPL.txt README.*

%changelog
* Sun Jan 12 2003 iNOUE Koich! <inoue@ma.ns.musashi-tech.ac.jp>
- Initial build.

