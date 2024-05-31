#!/usr/bin/perl

use strict;
use warnings;

use Term::ANSIColor;

use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;

sub print_payload {
    my ($data) = @_;
    my $payload_hex   = unpack("H*", $data);
    my $payload_ascii = $data;
    $payload_ascii =~ s/[^[:print:]]/./g;

    print "Payload (HEX):\n";
    print color("yellow"), "$payload_hex\n\n", color("reset");
    print "Payload (ASCII):\n";
    print color("cyan"), "$payload_ascii\n\n\n\n", color("reset");
}

sub packet_handler {
    my ($user, $header, $packet) = @_;

    my $length   = $header->{'len'};
    my $eth_obj  = NetPacket::Ethernet->decode($packet);
    my $ip_obj   = NetPacket::IP->decode($packet);


    if ($eth_obj->{'type'} == NetPacket::Ethernet::ETH_TYPE_IP) {
	my $ip_obj   = NetPacket::IP->decode($eth_obj->{'data'});
	my $src_ip   = $ip_obj->{'src_ip'};
	my $dst_ip   = $ip_obj->{'dest_ip'};
	my $protocol = $ip_obj->{proto};

	if ($protocol == 6) {
	    my $tcp_obj  = NetPacket::TCP->decode($ip_obj->{'data'});
	    my @flags;

	    push @flags, "FIN" if $tcp_obj->{flags} & 0x01;
	    push @flags, "SYN" if $tcp_obj->{flags} & 0x02;
	    push @flags, "RST" if $tcp_obj->{flags} & 0x04;
	    push @flags, "PSH" if $tcp_obj->{flags} & 0x08;
	    push @flags, "ACK" if $tcp_obj->{flags} & 0x10;
	    push @flags, "URG" if $tcp_obj->{flags} & 0x20;
	    push @flags, "ECE" if $tcp_obj->{flags} & 0x40;
	    push @flags, "CWR" if $tcp_obj->{flags} & 0x80;

	    print "TCP Flags: " . join(", ", @flags) . "\n";
	    print "Received <TCP>.\n";

	    print "DST addr: $dst_ip - ";
	    print "DST port: $tcp_obj->{dest_port}\n";
	    print "SRC addr: $src_ip - ";
	    print "SRC port: $tcp_obj->{src_port}\n";
	    print "Packet received - size: $length bytes\n\n";

	    print_payload($tcp_obj->{data});
	} 
	elsif ($protocol == 17) {
	    my $udp_obj  = NetPacket::UDP->decode($ip_obj->{'data'});
	    print "Received <UDP>.\n";

	    print "Checksum: ".  (defined $udp_obj->{'udp_cksum'} ? 
				  $udp_obj->{'udp_cksum'} : "N/A")."\n";

	    print "DST addr: $dst_ip - ";
	    print "DST port: $udp_obj->{dest_port}\n";
	    print "SRC addr: $src_ip - ";
	    print "SRC port: $udp_obj->{src_port}\n";
	    print "Packet received - size: $length bytes\n\n";

	    print_payload($udp_obj->{data});
	}
	else {
	    print "Received <Unknown> packet type.\n";
	    print "DST addr: $dst_ip -- \n";
	    print "SRC addr: $src_ip -- \n";
	    print "Packet received - size: $length bytes\n\n";
	}

    }
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
