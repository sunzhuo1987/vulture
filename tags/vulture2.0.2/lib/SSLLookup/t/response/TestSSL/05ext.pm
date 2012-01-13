package TestSSL::05ext;

use strict;
use warnings FATAL => qw(all);

use Apache::Test qw(-withtestmore);

use Apache2::Const -compile => qw(OK);

sub handler {

  my $r = shift;

  plan $r, tests => 4;

  {
    use_ok('Apache::SSLLookup');
  }

  {
    can_ok('Apache::SSLLookup', 'ext_lookup');
  }

  {
    $r = Apache::SSLLookup->new($r);

    ok(!$r->ext_lookup('060406142524Z'),
       'nothing to find on the server when not using ssl');

    ok(!$r->ext_lookup('060406142524Z'),
       'nothing to find on the client when not using ssl');
  }

  return Apache2::Const::OK;
}

1;
