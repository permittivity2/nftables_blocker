package NftablesBlocker::DefaultExtractor;

use strict;
use warnings;
use Fcntl qw(SEEK_END SEEK_SET);
use Log::Any qw($log);
use Data::Dumper;
use JSON qw(decode_json);

$Data::Dumper::Indent = 1;
$Data::Dumper::Sort = 1;

my $REGEX_IPV4 = q/\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b/;

# REGEX_IPV6 is not used and untested.  Provided here for future modules, add-ons, bolt-ons or for whomever to try.
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
    $log->info("Running run in " . __PACKAGE__ . " ...");

    my $bad_ips = $self->extract_bad_ips( $self->{args} );

    # Clean the bad IPs against the current nftables entries
    my $cleaned_bad_ips;
    my $table = $self->{args}->{nftables_setup}->{table};
    my $element = $self->{args}->{nftables_setup}->{element};
    my $nftables_element_set = _get_nftables_to_json( { table => $table, element => $element } );
    foreach my $bad_ip (@$bad_ips) {
        if ( _ip_in_nftables( { table => $table, element => $element, ip => $bad_ip, nftables_set => $nftables_element_set } ) ) {
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

        $self->{$logfile}->{$file}->{seek_pos} = $args->{read_all} ? 0 : tell($fh);
        close $fh;
    }

    return \@file_contents;
}


sub extract_bad_ips {
    my ($self, $args) = @_;
    $log->info("Running extract_bad_ips in " . __PACKAGE__ . " ...");

    my $files = $args->{files} || {};
    my $regexes = $args->{regexes} || {};
    
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

    my $combined_regex = join '|', values %$regexes;  # Using pipe to match any of the regexes

    # Hash to store unique bad IPs
    my %bad_ips;

    # Get the bad ips, keep lines that match the combined regex, extract the IP addresses in each line, and remove duplicates
    for my $line (@file_contents) {
        if ($line =~ /$combined_regex/) {
            while ($line =~ /$REGEX_IPV4/g) {
                $bad_ips{$&} = 1;
            }
        }
    }
    my @unique_bad_ips = keys %bad_ips;

    # $log->info("Unique bad IPs: " . Dumper(\@unique_bad_ips));
    return \@unique_bad_ips;
}

sub _ip_in_nftables {
    my $args = shift;
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
    my $args = shift;
    my $table = $args->{table};
    my $element = $args->{element};

    my $cmd = "nft -j list set inet $table $element";
    my $json_output = `$cmd`;
    my $nft_data = decode_json($json_output);
    my $nftables = $nft_data->{nftables};

    return $nftables;
}

1;
