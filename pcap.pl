#!/usr/bin/perl

use strict;
use warnings;
use Net::Pcap;

sub packet_handler {
	my ($user, $header, $packet) = @_;
	my $length = $header->{'len'};
	print "Packet received - size: $length bytes\n";
}

sub usage {
	my $progname = shift;
	print "Usage: $progname <network interface>\n";
	exit (1);
}


if ($0 eq __FILE__) {
	my $interface = shift || usage($0);
	my $err;
	my $pcap_handle = Net::Pcap::open_live ($interface, 65536, 1, 1000, \$err);

	if (!$pcap_handle) {
		die "Error while opening network adapter: $err\n";
	}

	Net::Pcap::loop  ($pcap_handle, 0, \&packet_handler, '');
	Net::Pcap::close ($pcap_handle);
}
