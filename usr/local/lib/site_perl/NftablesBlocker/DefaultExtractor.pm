package NftablesBlocker::DefaultExtractor;

use strict;
use warnings;
use Fcntl qw(SEEK_END SEEK_SET);
use Log::Any qw($log);
use Log::Log4perl::MDC;
use Data::Dumper;
use JSON qw(decode_json);

$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;

my $REGEX_IPV4 = q/\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b/;

# REGEX_IPV6 is not used and untested.  Provided here for future modules, add-ons, bolt-ons or for whomever to try.
# If you add IPv6 regex then you'll need to add a new element to the nft tables structure to store the IPv6 addresses.
# That also means new rules added as well to the chain to handle the new element.
# For whatever reason, nftables has different elements for IPv4 and IPv6 addresses.
# my $REGEX_IPV6 = qr/(
#     (?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|
#     (?:[A-Fa-f0-9]{1,4}:){1,7}:|
#     (?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|
#     (?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|
#     (?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|
#     (?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|
#     (?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|
#     [A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){1,6}|
#     :(?::[A-Fa-f0-9]{1,4}){1,7}|:
#     fe80:(?::[A-Fa-f0-9]{0,4}){0,4}%[0-9a-zA-Z]{1,}|
#     ::(ffff(?::0{1,4}){0,1}:){0,1}
#     (?:[0-9]{1,3}\.){3}[0-9]{1,3}|
#     (?:[A-Fa-f0-9]{1,4}:){1,4}:
#     (?:[0-9]{1,3}\.){3}[0-9]{1,3}
# )/x;

sub new {
    my ($class, $args) = @_;
    $log->info("Instantiating " . __PACKAGE__ . " object...");
    my $self = {
        args => $args,
    };
    bless $self, $class;
    return $self;
}

sub run {
    my $self = shift;
    $log->debug("Running run in " . __PACKAGE__ . " ...");

    my $bad_ips = $self->extract_bad_ips( $self->{args} );

    # Clean the bad IPs against the current nftables entries
    my $cleaned_bad_ips;
    my $table = $self->{args}->{nftables_setup}->{table};
    my $element = $self->{args}->{nftables_setup}->{element};
    my $nftables_element_set = $self->_get_nftables_to_json( { table => $table, element => $element } );
    foreach my $bad_ip (@$bad_ips) {
        if ( $self->_ip_in_nftables( { table => $table, element => $element, ip => $bad_ip, nftables_set => $nftables_element_set } ) ) {
            # $log->info("IP $bad_ip already in $table/$element.  Skipping.");
            next;
        }
        $log->info("IP $bad_ip is not in $table/$element.  Adding to the list.");
        push @$cleaned_bad_ips, $bad_ip;
    }

    return $cleaned_bad_ips;
}


sub _read_files {
    my ($self, $args) = @_;
    my $files = $args->{files};
    my $logfile = $args->{logfile};
    my @file_contents;

    if (!$files || !keys %$files) {
        $log->info("No files specified.");
        return [];
    }

    if (!$logfile) {
        $log->info("No logfile specified.");
        return [];
    }

    foreach my $file (sort keys %$files) {
        my $seek_pos = $self->{$logfile}->{$file}->{seek_pos} || 0;
        $log->debug("Seek positiion for $logfile -> $file: $seek_pos");
        my $filename = $files->{$file};

        my $fh;
        unless (open $fh, '<', $filename) {
            $log->info("Could not open file: $logfile -> $file -> $filename.  Skipping.");
            next;
        }

        seek $fh, $seek_pos, 0;

        my %seen;
        while (my $line = <$fh>) {
            next unless $line =~ /$REGEX_IPV4/;
            chomp $line;
            next if $seen{$line}++;
            push @file_contents, $line;
        }

        $log->debug("Read " . scalar @file_contents . " lines from $logfile -> $file -> $filename.");
        $log->trace("File contents: " . Dumper(\@file_contents));
        $self->{$logfile}->{$file}->{seek_pos} = $args->{read_all} ? 0 : tell($fh);
        $log->debug("New seek position for $logfile -> $file: " . $self->{$logfile}->{$file}->{seek_pos});
        close $fh;
    }

    return \@file_contents;
}


sub extract_bad_ips {
    my ($self, $args) = @_;
    my $files = $args->{files} || {};
    my $regexes = $args->{regexes} || {};
    my $ignore_regexes = $args->{ignore_regexes} || {};
    my $never_block = $args->{never_block} || {};
    my $always_block = $args->{always_block} || {};
    
    if (! keys %$files) {
        $log->info("No files specified.");
        return [];
    }

    if (! keys %$regexes) {
        $log->info("No regexes specified.");
        return [];
    }

    my $file_contents_ref = $self->_read_files($args) || [];
    my @file_contents = @$file_contents_ref;

    # Match the lines that contain the regexes
    my @matched_lines = $self->_match_lines( { file_contents => \@file_contents, regexes => $regexes } );

    # Remove the lines that match the ignore regexes
    @matched_lines = $self->_ignore_lines( { matched_lines => \@matched_lines, ignore_regexes => $ignore_regexes } );

    # Extract all the IPs from each @matched_lines and store them in %bad_ips
    #   This is some perl kung-fu.  It's a map within a grep within a map within a grep.
    my $bad_ips = { map { $_ => 1 } grep { /$REGEX_IPV4/ } map { /$REGEX_IPV4/g } @matched_lines };
    $log->debug("All possible bad IPs: " . join(", ", keys %$bad_ips));

    # Remove the IPs that should never be blocked
    $bad_ips = $self->_remove_never_block_ips( { bad_ips => $bad_ips, never_block => $never_block } );

    # Add in the always block IPs
    $bad_ips = $self->_add_always_block_ips( { bad_ips => $bad_ips, always_block => $always_block } );

    my @unique_bad_ips = keys %$bad_ips;
    $log->debug("Unique bad IPs: " . Dumper(\@unique_bad_ips));
    return \@unique_bad_ips;
}

sub _add_always_block_ips {
    my ($self, $args) = @_;
    my $bad_ips = $args->{bad_ips};
    my $always_block = $args->{always_block};
    my %unique_bad_ips = %$bad_ips;

    foreach my $always_block_ip (keys %$always_block) {
        $log->debug("Adding always block IP: $always_block_ip to the list.");
        if ( $self->_is_ipv4($always_block_ip) ) {
            $unique_bad_ips{$always_block_ip} = 1;
        } else {
            $log->warn("Always block IP: $always_block_ip is not a valid IPv4 address.");
        }
    }

    return \%unique_bad_ips;
}

# Description: a sub to veriify ifa string is an IPv4 address that may also contain a valid subnet
# Input: a string
# Output: a boolean
sub _is_ipv4 {
    my ($self, $ip) = @_;
    return $ip =~ /^$REGEX_IPV4(?:\/\d{1,2})?$/;
}

sub _remove_never_block_ips {
    my $self = shift;
    my $args = shift;
    my $bad_ips = $args->{bad_ips};
    my $never_block = $args->{never_block};
    my @unique_bad_ips;

    foreach my $bad_ip (keys %$bad_ips) {
        $log->trace("Checking bad IP: $bad_ip against never block IPs.");
        my $never_block_ip_found = 0;
        foreach my $never_block_ip (keys %$never_block) {
            if ($bad_ip =~ /$never_block_ip/) {
                $log->debug("Removing never block IP: $never_block_ip from the list.");
                $never_block_ip_found = 1;
                last;
            }
        }
        push @unique_bad_ips, $bad_ip unless $never_block_ip_found;
    }

    return \@unique_bad_ips;
}

sub _ignore_lines {
    my ($self, $args) = @_;
    my $matched_lines = $args->{matched_lines};
    my $ignore_regexes = $args->{ignore_regexes};
    my @filtered_lines;

    for my $line (@$matched_lines) {
        my $ignore = 0;
        foreach my $ignore_regex (keys %$ignore_regexes) {
            $log->trace("Checking line: $line against ignore regex: $ignore_regex");
            if ($line =~ /$ignore_regex/) {
                $log->debug("Ignoring line: $line against ignore regex: $ignore_regex");
                $ignore = 1;
                last;
            }
        }
        next if $ignore;
        push @filtered_lines, $line;
    }

    return \@filtered_lines;
}

sub _matched_lines {
    my ($self, $args) = @_;
    my $file_contents = $args->{file_contents};
    my $regexes = $args->{regexes};
    my @matched_lines;

    for my $line (@$file_contents) {
        foreach my $regex (keys %$regexes) {
            $log->trace("Checking line: $line against regex: $regex");
            if ($line =~ /$regex/) {
                $log->debug("Matched line: $line against regex: $regex");
                push @matched_lines, $line;
            }
        }
    }

    return \@matched_lines;
}

sub _ip_in_nftables {
    my ($self, $args) = @_;
    my $table = $args->{table};
    my $element = $args->{element};
    my $ip = $args->{ip};
    my $nftables = $args->{nftables_set} || _get_nftables_to_json( { table => $table, element => $element } );

    foreach my $nftable (@$nftables) { 
        if ( $nftable->{set}->{name} and 
                $nftable->{set}->{table} and 
                $nftable->{set}->{name} eq $element and 
                $nftable->{set}->{table} eq $table ) {
            my $elements = $nftable->{set}->{elem};
            foreach my $elem (@$elements) {
                my $actual_elem = $elem->{elem};
                if ( $actual_elem->{val} eq $ip ) {
                    my $expires = $actual_elem->{expires};
                    # $log->debug("IP $ip already in $table/$element but will be removed in $expires seconds.");
                    return 1;
                }
            }
        }
    }

    return 0;
}  ## end sub _ip_in_nftables

sub _get_nftables_to_json {
    my ($self, $args) = @_;
    my $table = $args->{table};
    my $element = $args->{element};

    my $cmd = "nft -j list set inet $table $element";
    my $json_output = `$cmd`;
    my $nft_data = decode_json($json_output);
    my $nftables = $nft_data->{nftables};

    return $nftables;
}

1;
