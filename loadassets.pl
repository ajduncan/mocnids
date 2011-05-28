#!/usr/bin/perl -w

use strict;
use POSIX;
use DBI;

my $asset_file  = "assets.csv";
my $db_database = "inphase";
my $db_username = "inphase";
my $db_password = "inphase";

my @asset_data;
my @asset_line;

my $temp;


# Open and read the asset data
open(FH, "<$asset_file") || die "Could not open $asset_file file.\n";
@asset_data = <FH>;
close(FH);

# Connect to the database
my $dbh = DBI->connect('DBI:mysql:' . $db_database, $db_username, $db_password) || die "Could not connect to the database: $DBI::errstr\n";

$temp = $dbh->do('delete from ipids_assets');
print "Cleared ipids_assets ($temp rows)\n";

# Insert the data from asset file to the database
$temp = 0;
foreach (@asset_data) {
  # ignore the first line.
  if ($temp == 1) {
    @asset_line = split(",", $_);
    $temp = POSIX::strftime("%Y-%m-%d %H:%M:%S\n", localtime($asset_line[5]));
    $dbh->do("insert into ipids_assets (asset, port, proto, service, application, discovered) values ('$asset_line[0]', '$asset_line[1]', '$asset_line[2]', '$asset_line[3]', '$asset_line[4]', '$temp')");
  }
  $temp = 1;
}

$dbh->disconnect();

print "Inserted asset data.\n";
