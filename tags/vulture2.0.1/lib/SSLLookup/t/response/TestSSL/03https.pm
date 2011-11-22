package TestSSL::03https;

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
    can_ok('Apache::SSLLookup', 'is_https');
  }

  {
    $r = Apache::SSLLookup->new($r);

    ok(defined $r->is_https,
       'is_https() returned a defined value');
  }

  return Apache2::Const::OK;
}

1;
