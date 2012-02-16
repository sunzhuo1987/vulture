Vulture 2 is a mod_perl Handler for Apache2.
For vulture to work properly, you will need to install some PERL modules.

We recommand to use CPAN:

cpan -i Apache2::ModProxyPerlHtml
cpan -i Apache::Session::Memcached
cpan -i Authen::Radius
cpan -i Crypt::CBC
cpan -i Crypt::OpenSSL::AES
cpan -i Data::HexDump
cpan -i Net::IP::Match::Regexp
cpan -i Authen::NTLM

Apache::SSLLookup is not in CPAN... but can be downloaded from http://search.cpan.org/CPAN/authors/id/G/GE/GEOFF/Apache-SSLLookup-2.00_04.tar.gz
For installation :

	tar xf Apache-SSLLookup-2.00_04.tar.gz
	cd Apache-SSLLookup-2.00_04
	perl Makefile.PL CCFLAGS="-I/usr/include/apr-1.0"
	make 
	make test
	make install
