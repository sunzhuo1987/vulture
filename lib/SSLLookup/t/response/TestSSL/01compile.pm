package TestSSL::01compile;

use strict;
use warnings FATAL => qw(all);

use Apache::Test qw(-withtestmore);

use Apache2::Const -compile => qw(OK);

sub handler {

  my $r = shift;

  plan $r, tests => 1;

  use_ok('Apache::SSLLookup');

  return Apache2::Const::OK;
}

1;
