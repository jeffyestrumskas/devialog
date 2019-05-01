#!/usr/bin/perl

################
# devialog: Copyright 2002-2007 Jeff Yestrumskas
#
# This file is part of devialog.
#
# devialog is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# devialog is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with devialog; if not, write to the Free Software
################

#use strict; not yet :>
use Getopt::Std;

my %opts;
getopts('l:c:m:r:t:hpCDo', \%opts);

my (%cfg, %tmpsig, %curmsg, $type, $file, $conf, $sigs, $total);

if (-f $opts{l} && $opts{c} && !$opts{h}) {
	$file = $opts{l};
	$conf = $opts{c};
	$sigs = $opts{r};
	$type = $opts{t};
} else {
die "Usage: ./devialogsig.pl <-l logfile> <-c output> <-t syslog|apache|windows> [-r sigfile] [-hp]
	-l <file> Use this logfile to create anomaly signature file
	-c <file> Output anomaly signatures to this file
	-C        Show line count as you go
	-o        Print one signature per line
	-p        Print results as you go
	-r <file> Read in previously created devialog signature base
	-t <type> Log type, i.e. syslog, apache, windows.  Presently only syslog is supported
	-D        Debug mode
	-h        This menu
";
}

# Our basic regex's for the various log types
# *nix syslog

#$cfg{global}{resyslog} = qr/^(\w{3}\s+\d+\s\d+:\d+:\d+)\s(\S+)\s(\S+):\s(.*)$/;
$cfg{global}{resyslog} = qr/^(\w{3}\s+\d+\s\d+:\d+:\d+)\s(\S+)\s(\S+\[\d+\]\:|\w+\:)\s+(.*)$/;

$cfg{global}{bresyslog} = qr/^(\w{3}\s+\d+\s\d+:\d+:\d+)\s(\S+)\s(.*)$/;

# Apache
$cfg{global}{reapache} = qr/^(\S+)\s+\-\s+(\S+)\s+\[(\d+)\/(\w+)\/(\S+)\s+(\S+)\]\s+\"(.*)\s+HTTP\/(\S+)\"\s+\d+\s+\d+/;

# Windows via EventReporter
$cfg{global}{rewindows} = qr/^(\w{3}\s+\d+\s\d+:\d+:\d+)\s+(\S+)\s+(\S+)\s+EvntSLog:\s\[(\w{3})\]\s(\w+)\/(\w+)\s\(\d+\)\s\-\s\"(.*)\"$/;

my $starttime = time;

print "Gathering line count from $file.. ";
my $wcl = `wc -l $file | awk \'{print \$1}\'`;
chop($wcl);
print "$wcl lines.  Now parsing.\n";
my $lc = 1;

my $count = 0;
my $first = 1;

if (-f $sigs) {
	require $sigs;
	print "Counting signatures from $sigs\n";
	my $k;
	do "$sigs";
	foreach $k (keys %sig) { $count++ }
	print "$count signatures read from $sigs\n";
}

my $r = "\n";
if ($opts{o}) { $r = ""; }

open(NEW, ">$conf");

# Before anything else is done, let's write the original signatures to a file.
my $i = 0;

foreach my $k (keys %sig) {
	$i++;
	print NEW "\$sig{anomaly$i} = {$r";
	if ($sig{$k}{comments}) {
		print NEW "\tcomments => '$sig{$k}{comments}',$r";
	} else {
		print NEW "\tcomments => 'This signature was likely created with a version of devialog prior to 0.8.5 before the comment field was created',$r";
	}
	if ($sig{$k}{line}) {
		my $makesafe = qr/$sig{$k}{line}/;
		print NEW "\tline => '$makesafe',$r";
	} else {
		print NEW "\tline => 'This signature was likely created with a version of devialog prior to 0.8.5 before the line field was created.  The actual syslog line will be placed here for future generated signatures',$r";
	}
	print NEW "\tmachine => '$sig{$k}{machine}',$r";
	print NEW "\tps => '$sig{$k}{ps}',$r";
	print NEW "\tmessage => '^$sig{$k}{message}\$',$r";
	print NEW "\taction => '$sig{$k}{action}'$r";
	print NEW "};\n$r";
}

open(FILE, "<$file");

while(defined(my $line=<FILE>)) {
	chomp($line);

	if ($line !~ /$cfg{global}{resyslog}|$cfg{global}{bresyslog}/) {
		if ($line !~ /last message repeated \d+ times/) {
			print STDERR "\nWarning - devialog was unable to recognize the format of the following line.  Please notify the author, jeff\@patriot.net\n";
			print STDERR "Warning - We are still parsing other lines and operation will continue as normal.\n";
			print STDERR "Warning - $line\n";
		}
		next;
	}

	# split the current syslog line
	syslog_split("$line");
	# generate a signature based off current syslog line
	gensig("$line");
	# if the new signature created does not match any known signatures, lets write it out
	if (match() == 0) {
		if ($opts{p}) { print_data(); }
		$count++;
		$sig{$count}{machine} = "$tmpsig{machine}";
		$sig{$count}{ps} = "$tmpsig{ps}";
		$sig{$count}{message} = "$tmpsig{message}";
		if ($count != 0) {
			if ($type eq "syslog") {
				print NEW "\$sig{anomaly$count} = {$r";
				if ($tmpsig{ps} eq "!BA!") {
					print NEW " comments => 'A more liberal syslog regex was used because this line is not a standard syslog format', $r";
				} else {
					print NEW " comments => 'insert comment here, if desired', $r";
				}
				#FIXME santize the line for things like 'hlt'
				$line =~ s/'/\\'/g;
				$line =~ s/`/\\`/g;
				print NEW " line => '$line', $r";
				print NEW " machine => '$tmpsig{machine}',$r";
				$tmpsig{ps} =~ s/\(/\\(/g;
				$tmpsig{ps} =~ s/\)/\\(/g;
				print NEW " ps => '$tmpsig{ps}',$r";
				$tmpsig{message} =~ s/'/\\'/g;
				$tmpsig{message} =~ s/`/\\`/g;
				print NEW " message => '^$tmpsig{message}\$',$r";
				print NEW " action => 'ignore'$r};\n$r";
			} elsif ($type eq "apache") {

			} elsif ($type eq "windows") {
				print NEW "\$sig{anomaly$count} = {$r type => '$curmsg{type}',$r level => '$curmsg{level}',$r srvname => '$curmsg{srvname}',$r message => '$tmpsig{message}',$r action => 'ignore'$r };\n";
			}
		}
	} else {
		debug("Signature matches, lets not add it");
	}
	if ($opts{C}) {
		print "line #$lc of $wcl, total signatures: $count\n";
	}
	$lc++;
}

close NEW;

#FIXME Should use Time::HiRes
my $totaltime = time - $starttime + .01;
my $lps = $wcl / $totaltime;

$totaltime = sprintf("%.2f", $totaltime);
$lps = sprintf("%.2f", $lps);

print "$count signatures written to $conf, generated from $file ($wcl lines) in $totaltime seconds.\nSpeed = $lps lines parsed per second.\n";

sub gensig {
	$line = $_[0];
	$tmpsig{message} = gen_regexp("$curmsg{message}");
	$tmpsig{ps} = "$curmsg{ps}";
	$tmpsig{machine} = "$curmsg{machine}";
	# die unless the newly created sig works
	# We should never ever get here.  This must be a really bizarre system log
	warn "Unable to create signature for: \"$line\"\n" unless (test_regexp("$curmsg{message}", "$tmpsig{message}") == 1);
}

sub print_data {
		print "total  : " . $total++ . "\n";
		print "machine: $curmsg{machine}\n";
		print "process: $curmsg{ps}\n";
		print "message: $curmsg{message}\n";
		print "regexp : $tmpsig{message}\n";
		print "test   : " . test_regexp($curmsg{message}, $tmpsig{regexp}) . "\n";
}

sub match {
	my $sigexists = 0;
	# let us loop through all the signatures and compare them to the current log line we're at
	# return 1 if the signature matches
	# return 0 if the signature doesnt match
	foreach my $k (keys %sig) { debug("KEYS $k"); }
	foreach my $k (keys %sig) {
		debug("COMPARING: MSG $tmpsig{machine} $tmpsig{ps} $tmpsig{message}");
		debug("COMPARING: SIG ${$sig{$k}}{machine} ${$sig{$k}}{ps} ${$sig{$k}}{message}");
		#if("${$sig{$k}}{ps}" eq "$tmpsig{ps}") {
			if("${$sig{$k}}{message}" eq "$tmpsig{message}") {
				# we already have a signature for this message, lets ignore it
				debug("PS $curmsg{ps} || ${$sig{$k}}{ps}");
				debug("MACHINE $curmsg{machine} || ${$sig{$k}}{machine}");
				debug("MESSAGE -$curmsg{message}- || ${$sig{$k}}{message}");
				$sigexists = 1;
				$first = 0;
				last;
			} 
		#}
	}
	if ($sigexists == 1) {
		debug("Signature exists");
		return 1;
	} else {
		debug("Did not match any current signatures");
		return 0;
	}
}

sub syslog_split {
	my $line = $_[0];
	$_ = $type;
	TYPE: {
		/syslog/ && do {
			if ($line =~ $cfg{global}{resyslog}) {
				$curmsg{date} = "$1";
				$curmsg{machine} = "$2";
				$curmsg{ps} = "$3";
				$curmsg{message} = "$4";
				if ($curmsg{ps} =~ /(\S+)\[(\d+)\]/) {
					$curmsg{ps} = $1;
					$curmsg{pid} = $2;
				} else {
					$curmsg{ps} = "$3";
					$curmsg{pid} = "0";
				}
      } elsif ($line =~ $cfg{global}{bresyslog}) {
          $curmsg{type} = "syslog";
          $curmsg{date} = "$1";
          $curmsg{machine} = "$2";
          # Hopefully unique identifier for ps to let check() know this line may very well be needing a backup regex
          $curmsg{ps} = "!BA!";
          $curmsg{pid} = "0";
          $curmsg{message} = "$3";
      }
		};
		/apache/ && do {
			if ($line =~ /^(\S+)\s+\-\s+(\S+)\s+\[(\d+)\/(\w+)\/(\S+)\s+(\S+)\]\s+\"(.*)\s+HTTP\/(\S+)\"\s+\d+\s+\d+/) {
				$curmsg{type} = "apache";
				$curmsg{machine} = "$1";
				$curmsg{user} = "$2";
				$curmsg{message} = "$7";
				$curmsg{protocol} = "$8";
			}
		};
		/windows/ && do {
			if ($line =~ /^(\w{3}\s+\d+\s\d+:\d+:\d+)\s+(\S+)\s+(\S+)\s+EvntSLog:\s\[(\w{3})\]\s(\w+)\/(\w+)\s\(\d+\)\s\-\s\"(.*)\"$/) {
				$curmsg{type} = "windows";
				$curmsg{date} = "$1";
				$curmsg{machine} = "$2";
				$curmsg{netbios} = "$3";
				$curmsg{level} = "$4";
				$curmsg{srvname} = "$5";
				$curmsg{source} = "$6";
				$curmsg{message} = "$7";
				return 0;
			} else {
				return 1;
			}
		};
	};
}

sub gen_regexp {
	my $line = $_[0];
	chomp($line);
	if ($curmsg{type} eq "windows") {
		if ($line =~ /^Delivery of message \S+.*in temporary file.*$/) {
			return("^Delivery\\sof\\smessage.*from.*temporary\\sfile\\s\\S+.*to.*\$");
		}
		if ($line =~ /^The following message could not be delivered.*$/) {
			return("^The following message could not be delivered.*\$");
		}
	}
	my ($regexp, @split, $foo);
	@split = split(/\s+/, $line);
	foreach $foo (@split) {
		$_ = $foo;
		SWITCH: {
			/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ && do {$regexp .= "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}";last SWITCH;};
			/^\S+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\S+$/ && do {$regexp .= "\\S+\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\S+";last SWITCH;};
			/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\S+$/ && do {$regexp .= "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\S+";last SWITCH;};
			/^\W+$/ && do {$regexp .= "\\S+";last SWITCH;};
			/^\d+$/ && do {$regexp .= "\\d+";last SWITCH;};
			/^\w+$/ && do {$regexp .= "$foo";last SWITCH;};
			/^\S+$/ && do {$regexp .= "\\S+";last SWITCH;};
			next;
		};
		$regexp .= "\\s+";
	}
	chop($regexp);
	chop($regexp);
	chop($regexp);
	return($regexp);
}

sub test_regexp {
	my ($line, $regexp) = @_;
	if ($line =~ /$regexp/) {
		return 1;
	} else {
		return 0;
	}
}

sub debug {
	my $it = $_[0];
	if ($opts{D}) {
		print STDERR "DEBUG: $it\n";
	}
}
