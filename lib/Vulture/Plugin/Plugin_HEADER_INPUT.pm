package Plugin::Plugin_HEADER_INPUT;
use Apache2::Log;
use Apache2::Reload;

use Apache2::Const -compile => qw(DECLINED);

sub plugin {
	my ($package_name, $r, $log, $dbh, $intf, $app, $header, $type, $options, $options1) = @_;
	$log->debug($header);
	if ($type eq "Header Add") {
		$r->headers_in->unset($header);
		$r->headers_in->set($header => $options);
	}
	if ($type eq "Header Modify") {
		if ($r->content_type =~ m/$header/i ) {
			$r->headers_in->unset($options);
			$r->headers_in->set($options => $options1);
		}
	}
	if ($type eq "Header Replacement") {
		$log->debug("Header Replacement");
		my @valhead = $r->headers_in->get($header);
		my $value = $options;
		my $replacementheader = $options1;
		foreach $headval (@valhead)
		{
			if ($headval && $headval =~ /$value/x)
			{
				$log->debug("Plugin_OutputFilterHandler RH Rule substitution OLDVAL=",$headval);
				$headval =~ s/$value/$replacementheader/ig;
				$log->debug("Plugin_OutputFilterHandler RH Rule substitution NEWVAL=",$headval);
				$r->headers_in->unset($header);
				$r->headers_in->set($header => $headval);
			}
		}
	}
	if ($type eq "Header Unset") {
		$log->debug("Header Unset");
		$r->headers_in->unset($header);
	}
} 
1;

