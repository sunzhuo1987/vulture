package TestSSL::04lookup;

use strict;
use warnings FATAL => qw(all);

use Apache::Test qw(-withtestmore);

use Apache2::Const -compile => qw(OK);

sub handler {

  my $r = shift;

  plan $r, tests => 3;

  {
    use_ok('Apache::SSLLookup');
  }

  {
    can_ok('Apache::SSLLookup', 'ssl_lookup');
  }

  {
    $r = Apache::SSLLookup->new($r);

    ok(!$r->ssl_lookup('foo'),
       'non-existent ssl variable returned false');
  }

  return Apache2::Const::OK;
}

1;
