#!/usr/bin/perl -w
#################################################################################### 
# 7 June 2010 AJD
# Simple Perl script to look at passive intrusion data from prads and snort data
# May be used to firewall out IPs exhibiting intrusive behavior
#
# Input:  snort data, prads data.
# Output: IPs that match intrusive behavior categorization.
#
#################################################################################### 

use strict;
use POSIX;
use DBI;

my $db_database   = "inphase";
my $db_username   = "inphase";
my $db_password   = "inphase";
my $snort_logfile = "/var/log/snort/alert";
my $prads_logfile = "/var/log/prads-asset.log";

# alert header;
my @alert_data;
my $alert_type       = "";
my $classification   = "";
my $priority         = "";
my $ts               = "";
my $src_ip           = "";
my $dst_ip           = "";

my %alerts = ();
my $alert_key;
my $alert_value;

my %blacklist = ();

my @temp;
my $t1;
my $t2;
my $t3;
my $t4;

# Log states:
# 1 = new alert
# 2 = Classification and Priority
# 3 = Timestamp, src ip/port dest ip/port
# 4 = unused
# 5 = unused
# 6 = reset

my $state = 6;

#################################################################################### 
# Snort alerts begin with [**] <some string for alert> [**]
# Statefully parse each alert:
#
#################################################################################### 
open(FH, "<$snort_logfile") || die "Could not open snort logfile ($snort_logfile): $!\n";
while (<FH>) {
  if (($state > 3) || ($state == 1)) {
    if (substr($_, 0, 4) eq "[**]") {
      if ($ts ne "") {
        # store the alert information in the hash
        @alert_data  = ($alert_type, $classification, $priority, $src_ip, $dst_ip);

        if (exists($alerts{$ts})) {
          print "Alert collission on time stamp: $ts for hash\n";
        } else {
          $alerts{$ts} = [ @alert_data ];
          # print "Alert ($alert_type) logged.\n";
        }

      
        # Reset the data
        @alert_data     = [];
        $ts             = "";
        $alert_type     = "";
        $classification = "";
        $priority       = "";
        $src_ip         = "";
        $dst_ip         = "";

        $state = 1;
        next;
      }

      @temp = split(/\[\*\*\]/, $_);
      $alert_type = $temp[1];
      $state = 2;
      next;

    }

  }

  # Collect Classification / Priority
  if ($state == 2) {
    if ($_ =~ /\[Classification: (.*?)\]/) {
      $classification = $1;
    }
    if ($_ =~ /\[Priority: (.*?)\]/) {
      $priority = $1;
    }

    $state = 3;
    next;
  }

  # Collect Timestamp, source, dest IP
  if ($state == 3) {
    @temp = split(/ /, $_);
    $t1 = $temp[0];
    $t2 = $temp[1];
    $t3 = $temp[2];
    $t4 = $temp[3];
    
    $ts     = $t1;
    $src_ip = (split(/:/, $t2))[0];
    $dst_ip = (split(/:/, $t4))[0];

    $state = 4;
    next;
  }

}
close(FH);

# Connect to the database
my $dbh = DBI->connect('DBI:mysql:' . $db_database, $db_username, $db_password) || die "Could not connect to the database: $DBI::errstr\n";

#################################################################################### 
# Now parse through the alerts and generate a snort blacklist
# 
#################################################################################### 
foreach $alert_key (keys %alerts) {
  $ts               = $alert_key;
  $alert_type       = ${$alerts{$alert_key}}[0];
  $classification   = ${$alerts{$alert_key}}[1];
  $priority         = ${$alerts{$alert_key}}[2];
  $src_ip           = ${$alerts{$alert_key}}[3];
  $dst_ip           = ${$alerts{$alert_key}}[4];

  # print "$ts : $alert_type : $classification : $priority : $src_ip : $dst_ip\n";

  # We don't care about internal traffic yet.
  if ($src_ip =~ /^192\.168\./) {
    # print "Ignoring IDS alert from internal network source.\n";
  } else {
    # Take Action:
    # print "$ts : $priority : $src_ip : $dst_ip\n";
    if (exists($blacklist{$src_ip})) {
    } else {

      # $t1 = POSIX::strftime("%Y-%m-%d %H:%M:%S\n", localtime($alert_key));
      $dbh->do("insert into ipids_attacks (ts, alert_type, classification, priority, src_ip, dst_ip) values ('$alert_key', '$alert_type', '$classification', '$priority', '$src_ip', '$dst_ip')");

      # Currently, we only have one prads rule (they use linux...);
      # Also check syn/ack/fin/rst
      $t1 = `grep $src_ip $prads_logfile | grep -m 1 Linux`;
      if (length($t1) > 1) {
        $blacklist{$src_ip} = 1;
        print $src_ip . "\n";
      }
    }
  }
}

$dbh->disconnect();

#################################################################################### 
#
# 
#################################################################################### 
