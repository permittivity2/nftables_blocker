package NftablesBlocker;

# Although not required, I strongly encourage using Log::Any for logging in your modules with sometnhing like the followiing:
#   use Log::Any::Adapter;  # Must be loaded before Log::Log4perl -- also, the NftablesBlocker module uses Log::Any.
#   use Log::Log4perl qw(get_logger);
#   Log::Any::Adapter->set('Log4perl');
# Thread IDs are set as part of a MDC usinig Log4perl.  Having the thread id will be a great help in debugging.
# I encourage the following log4perl layout:
#   log4perl.appender.LOG1.layout                        = Log::Log4perl::Layout::PatternLayout
#   log4perl.appender.LOG1.layout.ConversionPattern      = %d|%p|%l|%X{PID}|%X{TID}|%m{chomp}%n


use strict;
use warnings;
use Log::Any qw($log);
use Log::Any::Adapter;
use Log::Log4perl::MDC;
use Carp qw(croak);
use Config::File qw(read_config_file);
use DBI;
use threads;
use Thread::Queue;
use Module::Load;
use POSIX qw(sigaction SIGINT SIGTERM);
use threads::shared;
use Data::Dumper;
use JSON qw(decode_json encode_json);

$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;

my $exit_flag :shared = 0;

our $running = 1;  # Global variable to control the running state of the program

my $ip_block_queue :shared = Thread::Queue->new();

sub new {
    my ($class, %args) = @_;
    Log::Log4perl::MDC->put("TID", "TID:" . threads->tid());
    Log::Log4perl::MDC->put("PID", "PID:" . $$);
    $log->info("Instantiating NftablesBlocker object...");
    my $self = {
        config_file    => $args{config_file},
        lock_file      => $args{lock_file},
        scan_interval  => $args{scan_interval} // 10,
        db_file        => $args{db_file} || $log->error("db_file parameter is required") && croak("db_file parameter is required"),
        chain          => $args{chain} // 'firewall',
        element        => $args{element} // 'badipv4',
        table          => $args{table} // 'nftblocker',
        family         => $args{family} // 'inet',
        timeout        => $args{timeout} // '900s',
        module         => $args{module} // 'DefaultExtractor',
        configs        => {},
    };
    $log->info("Configuration: " . Dumper($self));
    bless $self, $class;

    # Check if nftables is installed
    $self->_check_nftables() or croak("nftables is not installed");

    if ( ! $self->_check_nftables_setup() ) {
        $self->_delete_nftables_chain() or croak("Could not delete nftables chain");
        $self->_create_nftables_chain() or croak("Could not create nftables chain");
    }
    else {
        $log->info("No change to nft.  nftables rules appear to be setup and ready.");
    }

    # Load regex patterns and modules from the configuration file
    $self->_load_config() or croak("Could not load configuration file");

    # Setup SQLite database   --- Future improvement, allow for other database types
    $self->_setup_database() or croak("Could not setup database");

    return $self;
}

sub _check_nftables {
    my $self = shift;
    my $nft_check = `nft --version 2>/dev/null`;
    if ($? != 0) {
        $log->error("nftables is not installed or not in the system PATH.");
        $log->info("To install and set up nftables on Ubuntu, follow these steps for Ubuntu:");
        $log->info("1. Install nftables: sudo apt-get install nftables");
        $log->info("2. Enable nftables service: sudo systemctl enable nftables");
        $log->info("3. Start nftables service: sudo systemctl start nftables");
        $log->info("4. Verify installation: sudo nft list tables");
        return 0;
    }
    $log->info("nftables is installed.");
}

sub _load_config {
    my $self = shift;
    $log->info("Loading configuration file: $self->{config_file}");
    my $config = read_config_file($self->{config_file});
    unless ($config) {
        $log->error("Could not read configuration file: $self->{config_file}");
        return 0;
    }
    $self->{configs} = $config;
    $log->info("Loaded configuration file: $self->{config_file}");
    # $log->debug("Configuration \$self->{configs}: " . Dumper($self->{configs}));

    # Load chain and element from config if not provided via command line
    $self->{chain} = $config->{chain} // $self->{chain};
    $log->info("Chain: $self->{chain}");
    $self->{element} = $config->{element} // $self->{element};
    $log->info("Element: $self->{element}");

    return 1;
}

sub _setup_database {
    my $self = shift;
    my $db_file = $self->{db_file};
    $log->info("Setting up database (only SQLite is supported): $db_file");
    my $dsn = "dbi:SQLite:dbname=$db_file";
    my $dbh = _get_DBH($dsn);

    unless ($dbh) {
        $log->error("Could not connect to database: $DBI::errstr");
        return 0;
    }

    eval {
        # Create table for IPs with unique constraint
        $dbh->do("CREATE TABLE IF NOT EXISTS ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE
        )");

        # Create table for Timestamps with unique constraint
        $dbh->do("CREATE TABLE IF NOT EXISTS timestamps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME UNIQUE
        )");

        # Create table for Log Files with unique constraint
        $dbh->do("CREATE TABLE IF NOT EXISTS log_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_file TEXT UNIQUE
        )");

        # Create bad_ips table with foreign keys pointing to the above tables
        $dbh->do("CREATE TABLE IF NOT EXISTS bad_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_id INTEGER,
            timestamp_id INTEGER,
            log_file_id INTEGER,
            FOREIGN KEY (ip_id) REFERENCES ips(id),
            FOREIGN KEY (timestamp_id) REFERENCES timestamps(id),
            FOREIGN KEY (log_file_id) REFERENCES log_files(id)
        )");

        $dbh->commit;
    };
    if ($@) {
        $log->error("Failed to set up database: $@");
        return 0;
    }

    $log->info("Database setup complete.");
    $dbh->disconnect;
    return 1;
}

# This is incomplete, untested, etc ----
sub _report {
    my $self = shift;
    my $dbh = _get_DBH($self->{db_file});
    my $qry = qq/
        SELECT
            b.id AS bad_ip_id,
            i.ip,
            datetime(t.timestamp, 'unixepoch') AS formatted_timestamp,
            lf.log_file
        FROM
            bad_ips b
        JOIN
            ips i ON b.ip_id = i.id
        JOIN
            timestamps t ON b.timestamp_id = t.id
        JOIN
            log_files lf ON b.log_file_id = lf.id
        ORDER BY
            t.timestamp DESC;
    /;
    my $sth = $dbh->prepare($qry);
    $sth->execute;
    while (my $row = $sth->fetchrow_hashref) {
        $log->info("IP: $row->{ip} from $row->{logfile} jailed at $row->{formatted_timestamp}");
    }
    $dbh->disconnect;
}


sub run {
    my $self = shift;

    # Signal handling for graceful shutdown
    my $sig_handler = sub {
        $exit_flag = 1;
        # $self->{ip_block_queue}->enqueue(undef);  # Unblock the blocking thread
        $ip_block_queue->enqueue(undef);  # Unblock the blocking thread
        $log->info("Shutting down...");
    };
    sigaction(SIGINT,  POSIX::SigAction->new($sig_handler));
    sigaction(SIGTERM, POSIX::SigAction->new($sig_handler));

    # Create queue for all activity
    my $queue = Thread::Queue->new();

    # Start the IP blocking thread
    my $sub_block_ip_args = {
        # ip_block_queue => $self->{ip_block_queue},
        chain          => $self->{chain},
        element        => $self->{element},
        table          => $self->{table},
        db_file        => $self->{db_file},
        timeout        => $self->{timeout},
        # queue          => $queue,
    };
    # my $ip_block_thread = threads->create(\&block_ips, $self->{ip_block_queue}, $self->{chain}, $self->{element});
    my $ip_block_thread = threads->create(\&block_ips, $sub_block_ip_args);

    $log->info("Started IP blocking thread");

    # Start the log file processing threads
    my @threads;

    $log->debug("Dump of self: " . Dumper($self));

    foreach my $log_to_review (sort keys %{$self->{configs}->{logfile}}) {
        my $log_config = $self->{configs}->{logfile}->{$log_to_review};
        $log_config->{logfile} = $log_to_review;
        $log_config->{nftables_setup} = $sub_block_ip_args;
        $log->info("Starting thread to review log file: $log_to_review");
        push @threads, threads->create(\&process_log_file, $log_config);
    }

    foreach my $thr (@threads) {
        $thr->join();
    }

    # Join the IP blocking thread
    $ip_block_thread->join();
}

sub block_ips {
    my $args = shift;
    Log::Log4perl::MDC->put("TID", "TID:" . threads->tid());
    # my $queue = $args->{ip_block_queue};
    my $chain = $args->{chain};
    my $table = $args->{table};
    my $element = $args->{element};
    my $db_file = $args->{db_file};
    $log->info("Thread to read and process queue to block IPs starting...");

    # Get database handle
    my $dsn = "dbi:SQLite:dbname=$db_file";
    my $dbh = _get_DBH($dsn) or $log->error("Could not connect to database: $DBI::errstr") && return 0;

    # while (my $ip = $queue->dequeue()) {
    while (my $q_item = $ip_block_queue->dequeue()) {
        last unless defined $q_item;  # Exit on undef
        my $ip = $q_item->{ip};

        if ( _ip_in_nftables( { table => $table, element => $element, ip => $ip } ) ) {
            $log->info("IP $ip already in nftables $table/$element");
            next;
        }

        my $logfile = $q_item->{logfile};
        # $log->info("Blocking IP: $ip from $logfile");
        my $cmd = "nft add element inet $table $element { $ip } ";
        # $log->info("Running command: $cmd");

        # If system command is successful write to database
        if ( system($cmd) == 0 ) {
            $log->info("IP $ip added to $table/$element");
            _add_bad_ip_to_db({ dbh => $dbh, ip => $ip, logfile => $logfile });
        } else {
            $log->error("Could not add IP $ip to $table/$element");
        }
    }
    $dbh->disconnect;
}


#  I actually put this sub for checking if the IP is already in nftables into the DefaultExtractor module
#   it's not functionally needed here.  I am not for sure a good reason to actually have this but leaving it
#   in but commented but always return 0.
#   There is no harm in trying to add an IP to an element set that already has the IP in it.
sub _ip_in_nftables {
    return 0;

    # Everything below here doesn't seem needed but not 100% for sure if I want to utilize this sub or not.
    my $args = shift;
    my $table = $args->{table};
    my $element = $args->{element};
    my $ip = $args->{ip};

    my $cmd = "nft -j list set inet $table $element";
    my $json_output = `$cmd`;
    my $nft_data = decode_json($json_output);
    my $nftables = $nft_data->{nftables};
    foreach my $nftable (@$nftables) {
        if ( $nftable->{set}->{name} and
                $nftable->{set}->{table} and
                $nftable->{set}->{name} eq $element and
                $nftable->{set}->{table} eq $table ) {
            my $elements = $nftable->{set}->{elem};
            foreach my $elem (@$elements) {
                my $actual_elem = $elem->{elem};
                if ( $actual_elem->{val} eq $ip ) {
                    $log->info("IP $ip already in $table/$element");
                    return 1;
                }
            }
        }
    }

    return 0;
}  ## end sub _ip_in_nftables

sub _add_bad_ip_to_db {
    my $args = shift;
    my $dbh = $args->{dbh};
    my $ip = $args->{ip};
    my $logfile = $args->{logfile};
    my $timestamp = $args->{timestamp} || time; # Default to current time in epoch seconds
    my $error = 0;

    eval {
        # Insert or retrieve IP
        my $ip_id = _get_or_insert_id($dbh, 'ips', 'ip', $ip);

        # Insert or retrieve Timestamp
        my $timestamp_id = _get_or_insert_id($dbh, 'timestamps', 'timestamp', $timestamp);

        # Insert or retrieve Log File
        my $log_file_id = _get_or_insert_id($dbh, 'log_files', 'log_file', $logfile);

        # Insert into bad_ips
        my $qry = "INSERT INTO bad_ips (ip_id, timestamp_id, log_file_id) VALUES (?, ?, ?)";
        $dbh->do($qry, undef, $ip_id, $timestamp_id, $log_file_id) or die "Could not add IP $ip to database";
    };
    if ($@) {
        $log->error("Failed to add bad IP to database: $@");
        $error = 1;
    }

    return !$error;
}

sub _get_or_insert_id {
    my ($dbh, $table, $column, $value) = @_;
    my $id;

    # Check if the value already exists
    my $qry = "SELECT id FROM $table WHERE $column = ?";
    my $sth = $dbh->prepare($qry);
    $sth->execute($value);
    ($id) = $sth->fetchrow_array;

    # If not, insert it
    if (!$id) {
        $dbh->do("INSERT INTO $table ($column) VALUES (?)", undef, $value) or die "Failed to insert into $table";
        $id = $dbh->last_insert_id(undef, undef, $table, 'id');
    }

    return $id;
}


sub _check_nftables_setup {
    my $self = shift;
    my $chain = $self->{chain};
    my $element = $self->{element};
    my $table = $self->{table};
    my $family = $self->{family};

    # Run the command to get the entire ruleset in JSON format
    my $cmd = "nft -a -j list ruleset";
    $log->info("Running command to get the complete nftables ruleset in JSON: $cmd");
    my $output = `$cmd`;

    # Decode the JSON output
    my $nftables_data = decode_json($output);

    # Check if the required table exists
    my $tables = $nftables_data->{nftables};
    my $table_exists = grep { $_->{table}->{name} eq $table && $_->{table}->{family} eq $family } @$tables;
    unless ($table_exists) {
        $log->debug("nftables table $table does not exist");
        return 0;
    }

    # Check if the required chain exists
    my $chains = [ grep { exists $_->{chain} } @$tables ];
    my $chain_exists = grep { $_->{chain}->{name} eq $chain && $_->{chain}->{table} eq $table } @$chains;
    unless ($chain_exists) {
        $log->debug("nftables chain $chain does not exist");
        return 0;
    }

    # Check if the required set (element) exists
    my $sets = [ grep { exists $_->{set} } @$tables ];
    my $set_exists = grep { $_->{set}->{name} eq $element && $_->{set}->{table} eq $table } @$sets;
    unless ($set_exists) {
        $log->debug("nftables set $element does not exist");
        return 0;
    }

    $log->debug("nftables setup appears to be complete. Here is the ruleset: \n$output");
    return 1;
}


sub _delete_nftables_chain {
    my $self = shift;
    my $chain = $self->{chain};
    my $table = $self->{table};
    my $family = $self->{family};

    # nft delete chain inet nftblocker firewall

    my $cmd = "nft delete chain $family $table $chain";
    $log->info("Running command to delete nft chain: $cmd");
    system($cmd) == 0 and $log->info("Deleted nftables chain $chain")
        or $log->error("Could not delete nftables chain $chain.  Full command: $cmd");

    $cmd = "nft delete table $family $table";
    $log->info("Running command to delete nft table: $cmd");
    system($cmd) == 0 and $log->info("Deleted nftables table $table")
        or $log->error("Could not delete nftables table $table.  Full command: $cmd");

    return 1;
}

sub _create_nftables_chain {
    my $self = shift;
    my $chain = $self->{chain};
    my $element = $self->{element};
    my $table = $self->{table};
    my $timeout = "900s" || $self->{timeout};
    my $family = $self->{family};

    my $cmd = "nft add table $family $table";
    $log->info("Running command to create nft $table: $cmd");
    system($cmd) == 0 and $log->info("Created nftables table $table")
        or $log->error("Could not create nftables table $chain.  Full command: $cmd");

    $cmd = "nft add chain $family $table $chain { type filter hook input priority 0 \\; }";
    $log->info("Running command to create nft chain: $cmd");
    system($cmd) == 0 and $log->info("Created nftables chain $chain")
        or $log->error("Could not create nftables chain $chain.  Full command: $cmd");

    # $cmd = "nft add set $family $table $element { type ipv4_addr \\; flags timeout \\; timeout 15m \\; }";
    $cmd = "nft add set $family $table $element { type ipv4_addr \\; flags timeout \\; timeout $timeout \\; }";
    $log->info("Running command to create nft timeout element: $cmd");
    system($cmd) == 0 and $log->info("Created nftables set $element")
        or $log->error("Could not create nftables set $element.  Full command: $cmd");

    $cmd = "nft add rule $family $table $chain ip saddr \@badipv4 counter drop";
    $log->info("Running command: $cmd");
    system($cmd) == 0 and $log->info("Set nft to drop and count packets for source addresses in $element")
        or $log->error("Could not set nft to drop and count packets for source addresses in $element.  Full command: $cmd");


    $cmd = "nft add rule inet $table $chain ip daddr \@badipv4 counter drop";
    $log->info("Running command: $cmd");
    system($cmd) == 0 and $log->info("Set nft to drop and count packets for destination addresses in $element")
        or $log->error("Could not set nft to drop and count packets for destination addresses in $element.  Full command: $cmd");

    return 1;
}

sub _get_DBH {
    my $dsn = shift or croak("dsn parameter is required");
    my $dbh = DBI->connect($dsn, "", "", {
            PrintError       => 1,
            RaiseError       => 1,
            AutoCommit       => 1,
        }
    ) or croak("Could not connect to database: $DBI::errstr");
    return $dbh;
}

sub process_log_file {
    my $args = shift;
    Log::Log4perl::MDC->put("TID", "TID:" . threads->tid());
    $log->debug("Dump of args: " . Dumper($args));

    my $module = $args->{module} || "DefaultExtractor";
    $module = "NftablesBlocker::" . $module;
    $log->info("Loading module: $module");
    load $module || $log->error("Unable to load module $module") && return 0;

    my $scan_interval = int($args->{scan_interval} // 10);

    my $review_log_module = $module->new($args);

    while ( 1 ) {
        my $bad_ips = $review_log_module->run();

        last if $exit_flag;  # Early exit flag check.  No need to add IPs to the queue if we are exiting.

        my $logmsg = $bad_ips ? join(", ", @$bad_ips) : "none";
        $log->debug("Bad IPs: " . $logmsg);
        $args->{bad_ips} = $bad_ips;
        # $log->info("Args to add bad IPs to queue: " . Dumper($args));
        _add_bad_ips_to_queue($args) or $log->error("Could not add bad IPs to queue");

        for (my $i = 0; $i < $scan_interval; $i++) {
            $log->info("Gracefully exitting the thread for $args->{logfile}") && last if $exit_flag;
            sleep 1;
        }

        last if $exit_flag;  # This seems duplicate but no need to add IPs to the queue or wait for next scan interval if we are exiting
    }

    $log->info("Exiting thread for $args->{logfile} and module $module");

    return 1;
}

sub _scan_interval_sleeper {
    my $scan_interval = shift;
    for (my $i = 0; $i < $scan_interval; $i++) {
        $log->info("Gracefully exitting the thread") && last if $exit_flag;
        sleep 1;
    }
}

sub _add_bad_ips_to_queue {   # This is a "private" method and has no access to $self
    my ($args) = @_;
    my $bad_ips = $args->{bad_ips};
    my $logfile = $args->{logfile};

    my @q_args;
    # foreach my $ip (@$bad_ips) {
    #     push @q_args, { logfile => $logfile, ip => $ip };
    # }
    @q_args = map { { logfile => $logfile, ip => $_ } } @$bad_ips;

    # for testing remove all but 2 of the entries oon @q_args
    # $log->info("TESTING TESTING TESTING Removing all but 2 entries from the queue");
    # splice @q_args, 2;

    $log->debug("No bad IPs to queue") and return 1 if (!@q_args);

    $log->debug("Adding IPs to queue: " . Dumper(\@q_args));
    # $ip_block_queue->enqueue(@q_args) and return 1;
    my $error = 0;

    foreach my $ip_log (@q_args) {
        eval { $ip_block_queue->enqueue($ip_log); };
        if ($@) {
            $error++;
            $log->error("Could not add IP to queue: " . Dumper($ip_log));
        }
    }
    if ($error) {
        $log->error("Could not add IPs to queue.  Something went wrong.");
        return 0;
    }

    return 1;
}

sub DESTROY {
    my $self = shift;
    $log->info("Destroying NftablesBlocker object...");
}

1;
