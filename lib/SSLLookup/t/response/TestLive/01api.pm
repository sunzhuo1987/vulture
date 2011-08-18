package TestLive::01api;

use strict;
use warnings FATAL => qw(all);

use Apache::Test qw(-withtestmore);

use Apache2::Const -compile => qw(OK);

use Apache::SSLLookup;

sub handler {

  my $r = shift;

  plan $r, tests => 6;

  $r = Apache::SSLLookup->new($r);

  SKIP : {
    skip 'apache 2.0.51 required', 1
      unless have_min_apache_version('2.0.51');

    ok($r->is_https,
       'is_https() returned true');
  }

  ok($r->ssl_lookup('https'),
     'HTTPS variable returned true');

  is($r->ssl_lookup('ssl_client_verify'),
     'NONE',
     'SSL_CLIENT_VERIFY returned ssl.conf value');

  SKIP : {
    skip 'apache 2.1.3 required', 2 
      unless have_min_apache_version('2.1.3');

    TODO : {
      local $TODO = "ext_lookup() is experimental";

      is($r->ext_lookup('2.5.4.3'),
         '???',
         'server');

      is($r->ext_lookup('2.5.4.3', 1),
         '???',
         'client');
    }
  }

  # can we still call $r methods?

  my $ct = $r->content_type;

  like ($ct,
        qr!text/plain!,
        'successfully called $r->content_type()');

  return Apache2::Const::OK;
}

1;
__DATA__
<NoAutoConfig>
</NoAutoConfig>
