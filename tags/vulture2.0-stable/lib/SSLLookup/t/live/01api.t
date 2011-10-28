use strict;
use warnings FATAL => qw(all);

use Apache::Test;
use Apache::TestRequest;

my $hostport = Apache::Test::config
                ->{vhosts}
                ->{TestLive}
                ->{hostport};

my $url = "https://$hostport/TestLive__01api/";

print GET_BODY_ASSERT $url;

