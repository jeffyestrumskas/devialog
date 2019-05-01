#!/usr/bin/perl

################
# devialog: Copyright 2002-2007 Jeff Yestrumskas - jeff@yestrumskas.com
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
# along with devialog; if not, write to:
#
# Free Software Foundation, Inc.
# 51 Franklin St, Fifth Floor
# Boston, MA  02110-1301  USA
################
# devialog 0.9.0

use strict;
use Getopt::Std;
use File::Tail;
use Socket;
use Mail::Sendmail;

my $conf = 'devialog.conf';

my %opts;
getopts('c:dhv', \%opts);

if ($opts{h}) { printhelp(); exit;}

my (%cfg, %curmsg, %tmpsig, %lastmsgqueue, %mailqueue, %mail, $dir, @data);

our %sig;

if (-f $opts{c}) { $conf = $opts{c}; }

readcfg("$conf");

# Flush!
$| = 1;

# Spawns new proccess for each watched file, as defined in the config
foreach my $dir (keys %cfg) {
	next if ($dir eq "global");
	next if (fork);

	$SIG{HUP} = sub {
		print STDERR "HUP received on $0, pid $$. Reloading: ";
		undef %cfg;
		print STDERR "$conf ";
		readcfg("$conf");
		print STDERR "$cfg{$dir}{signature} \n";
		require "$cfg{$dir}{signature}";
	};

	#debug("requiring: $cfg{$dir}{signature} $dir");
	require "$cfg{$dir}{signature}";
	
	# Continuously monitor each file
	my $name = $cfg{$dir}{file};

	# Display some stats about the running processes
	print STDERR "Forked devialog to background, monitoring $name for anomalies and known signatures.\n";
	foreach (split(/,/, $cfg{$dir}{anomaly})) {
		SWITCH: {
			/outfile/ && do {print "Will write anomalies in $name to $cfg{$dir}{outfile}\n";};
			/mail/ && do {print "Will email anomalies in $name to $cfg{$dir}{rcpts}\n";};
			/print/ && do {
					print "Will print anomalies in $name to the screen";
					if ($cfg{$dir}{card} == 1) { print " in the the form of an alert card"; }
					print "\n";
				};
			/external=<(.*)>/ && do {
				print "Will respond to anomalies in $name by executing $1\n";
			}
		};
	}
	if ($cfg{$dir}{suggestloc}) { print "Will write suggested signatures to $cfg{$dir}{suggestloc}\n"; }
	
	my $line;
	my $file;
	my $nfound;
	my $timeleft;
	my $pending;
	my $timeout;
	my $now;
	my $thresh;

	$thresh = time;
	$timeout = 1;
	$file = File::Tail->new(name=>"$name");

	while(1) {
		($nfound,$timeleft,$pending)=File::Tail::select(undef,undef,undef,$timeout,$file);

		# If mail queueing is enabled, let's handle just about everything required for it here
		if ($cfg{$dir}{qmail} == 1) {
			$now = time;
			if (($now - $thresh) > $cfg{$dir}{qthresh} && $mailqueue{total} > 0) {
				my $sbj;
				my $plural;
				if ($mailqueue{total} > 1 && $mailqueue{message}) {
					#debug("main while(): mqueue=>1 dir=$dir cfgdirqsubject=$cfg{$dir}{qsubject}");
					$sbj = qtrsubject("$cfg{$dir}{qsubject}");
					mailsend("$cfg{$dir}{from}","$cfg{$dir}{rcpts}","$sbj", "$cfg{$dir}{sublimit}", "$cfg{$dir}{subresolve}", "$mailqueue{head}\n$mailqueue{message}");
				} elsif ($mailqueue{total} == 1 && $mailqueue{message}) {
					#debug("main while(): mqueue=0 dir=$dir cfgdirqsubject=$cfg{$dir}{subject}");
					$sbj = trsubject("$cfg{$dir}{subject}");
					mailsend("$cfg{$dir}{from}","$cfg{$dir}{rcpts}","$sbj", "$cfg{$dir}{sublimit}", "$cfg{$dir}{subresolve}", "$mailqueue{head}\n$mailqueue{message}");
				}
				undef %mailqueue;
				%mailqueue;
				$mailqueue{total} = 0;
				$thresh = time;
			}
		}
		unless ($nfound) {
			next;
		} else {
			$line = $file->read;
		}

		chomp($line);	
		#debug("line: $line");

		if ($line !~ /$cfg{global}{resyslog}/ || /$cfg{global}{bsyslog}/) {
			if ($line !~ /last message repeated \d+ times/) {
				print STDERR "\nWarning - devialog was unable to recognize the format of the following line.  Please notify the author, jeff\@yestrumskas.com\n";
				print STDERR "Warning - Do not worry!  devialog is still parsing other lines and operation will continue as normal.\n";
				print STDERR "Warning - $line\n";
			}
			next;
		}
		# Split the log line
		splitmsg("$cfg{$dir}{type}", "$line");
		# Check it, is it an anomaly?  Whatever it is, $chkret knows
		my $chkret = check("$cfg{$dir}{type}");
		if ($chkret =~ /\w+(\d+)/) {
		# Signature $1 has matched, do it's action, if any
			my @s = split(/\s+/, $sig{$chkret}{action});
			#debug("main: just about to do actions: $sig{$chkret}{action} - $chkret - $sig{$chkret}{action} - @s");
			foreach my $foo (@s) {
				action("$foo");
			};
		} elsif ($chkret eq "anomaly") {
		# This line is an anomaly, we shall do each action in $cfg{$dir}{anomaly}
			#debug("anomaly, actions: $cfg{$dir}{anomaly}");
			my @s = split(/\s+/, $cfg{$dir}{anomaly});
			foreach my $foo (@s) {
				action("$foo", "$dir");
			};
			#FIXME: make me more efficient
			if ($cfg{$dir}{suggestloc}) {
				my @data;
				my $re = genregexp($curmsg{message});
				push(@data, "\$sig{anomaly0} = {\n");
				if ($curmsg{ps} eq "!BA!") {
					push(@data, "\tcomments => 'A liberal syslog regex was used because this line is not a standard syslog format',\n");
				} else {
					push(@data, "\tcomments => 'insert comment here, if desired',\n");
				}
				my $escline = $curmsg{full};
				$escline =~ s/\'/\\'/g;
				$escline =~ s/\`/\\`/g;
				push(@data, "\tline => '$escline',\n");
				if ($cfg{$dir}{wcsuggest} == 1) {
					push(@data, "\tmachine => '.*',\n");
				} else {
					push(@data, "\tmachine => '$curmsg{machine}',\n");
				}
				my $tmpps = $curmsg{ps};
				$tmpps =~ s/\(/\\(/g;
				$tmpps =~ s/\)/\\)/g;
				push(@data, "\tps => '$tmpps',\n");
				push(@data, "\tmessage => '^$re\$',\n");
				push(@data, "\taction => 'ignore'\n");
				push(@data, "};\n\n");
				open(SUGGEST, ">>$cfg{$dir}{suggestloc}") or die "Can't open $cfg{$dir}{suggestloc} for writing: $!\n";
				print SUGGEST "@data";
				close SUGGEST;
			}
		}
	}
}

sub action {
	my ($action, $dir) = @_;
	#debug("action() start, action='$action', type='$cfg{$dir}{type}'");
	$_ = $action;
	ACTION: {
		#/ignore/ && do { last ACTION; };
		/mail/ && do {
			#debug("action() email start, type $cfg{$dir}{type}");
			if ($cfg{$dir}{type} eq "syslog") {
				#debug("action() email syslog type");

				if ($cfg{$dir}{card} == 1 && $cfg{$dir}{qmail} != 1) {
					my @data = mkcard("$cfg{$dir}{type}", "$dir");
				} 

				if ($cfg{$dir}{suggest} == 1) {
					my $re = genregexp($curmsg{message});
					push(@data, "\$sig{anomaly0} = {\n");
					if ($curmsg{ps} eq "!BA!") {
						push(@data, "\tcomments => 'A more liberal syslog regex was used because this line is not a standard syslog format',\n");
					} else {
						push(@data, "\tcomments => 'insert comment here, if desired',\n");
					}
					my $escline = $curmsg{full};
					$escline =~ s/\'/\\'/g;
					push(@data, "\tline => '$escline',\n");
					if ($cfg{$dir}{wcsuggest} == 1) {
						push(@data, "\tmachine => '.*',\n");
					} else {
						push(@data, "\tmachine => '$curmsg{machine}',\n");
					}
					my $tmpps = $curmsg{ps};
					$tmpps =~ s/\(/\\(/g;
					$tmpps =~ s/\)/\\)/g;
					push(@data, "\tps => '$tmpps',\n");
					push(@data, "\tmessage => '^$re\$',\n");
					push(@data, "\taction => 'ignore'\n");
					push(@data, "};\n");
				}

				my @tmpalert = split(//, $curmsg{message});

				my $subject = trsubject("$cfg{$dir}{subject}");

				if ($cfg{$dir}{qmail} == 1) {
					# line below prepares in the event
					mailaddqueue("@data");
					#debug("action() type=queueing syslog email for later sending");
				} else {
					mailsend("$cfg{$dir}{from}","$cfg{$dir}{rcpts}","$subject", "$cfg{$dir}{sublimit}", "$cfg{$dir}{subresolve}", "$curmsg{full}\nSuggested Signature:\n@data");
					#debug("action() type=syslog email sent");
				}
				undef @data;
				#debug("action() type=syslog email switch end");
			}
			if ($cfg{$dir}{type} eq "apache") {
				# Add apache log mailing support
			}
			if ($cfg{$dir}{type} eq "windows") {
				# Finish windows log mailing support
				if ($cfg{$dir}{card} == 1) { my @data = mkcard("$cfg{$dir}{type}", "$dir"); }
				push(@data, "\r\n\r\n\$sig{anomaly00} = {\r\n");
				push(@data, "\ttype => '$curmsg{type}'\r\n");
				push(@data, "\tlevel => '$curmsg{level}'\r\n");
				push(@data, "\tsrvname => '$curmsg{srvname}'\r\n");
				push(@data, "\tmessage => '^$tmpsig{message}\$'\r\n");
				push(@data, "\taction => 'ignore'\r\n");
				push(@data, "};\r\n");
				my @tmpalert = split(//, $curmsg{message});
				my $subject = "$cfg{$dir}{subject}\@$curmsg{machine}: ";
				for my $j (0 .. 50) { $subject .= "$tmpalert[$j]"; }
				#debug("action() type=windows before mailsend(): \"$cfg{$dir}{from}\", \"$cfg{$dir}{rcpts}\", \"$subject\", \"@data\"");
				mailsend("$cfg{$dir}{from}", "$cfg{$dir}{rcpts}", "$subject", "$cfg{$dir}{sublimit}", "$cfg{$dir}{subresolve}", "@data");
				#debug("action() type=windows email end");
			}
		};
		# Print the log (with pretty ascii card if FormCard is yes) to the screen
		/print/ && do {
			if ($cfg{$dir}{card} == 1) {
				print mkcard("$cfg{$dir}{type}", "$dir") unless $cfg{$dir}{quiet} == 1;
			} else {
				print "$curmsg{full}\n" unless $cfg{$dir}{quiet} == 1;
			}
		};
		# Action executes external command
		/external=<(.*)>/ && do {
			my $ext = $1;
			system("$ext");
		};
		# Prints log to file.  Use then when matching to a KNOWN signature, not anomalies
		/outfile=<(.*)>/ && do {
			my $outfile = $1;
			open(OF, ">>$1");
			print OF "$curmsg{full}\n";
			close OF;	
			#debug("action() outfile (nonanomaly) end");
			last ACTION;
		};
		# Print log anomaly to external file.  Use this action for anomalies, not KNOWN signatures
		/outfile/ && do {
			#debug("action() outfile begin");
			open(OF, ">>$cfg{$dir}{outfile}") or warn "Can't print to $cfg{$dir}{outfile}: $!\n";
			print OF "$curmsg{full}\n";
			close OF;	
			#debug("action() (anomaly) outfile end");
		};
	};
}

sub check {
	TYPE: {
		/syslog/ && do {
			my $k;
			#debug("what we see: ps: $curmsg{ps} machine: $curmsg{machine} message: $curmsg{message} || $sig{$k}{ps} - $sig{$k}{machine} - $sig{$k}{message}");
			foreach $k (keys %sig) {
				#debug("check() sig: $k if (/$curmsg{ps}/ !~ /$sig{$k}{ps}/)");
				next if ($curmsg{ps} !~ /$sig{$k}{ps}/);
				#debug("check() sig: $k if ($curmsg{machine} !~ /$sig{$k}{machine}/)");
				next if ($curmsg{machine} !~ /$sig{$k}{machine}/);
				#debug("check() sig: $k - if ($curmsg{message} !~ /$sig{$k}{message}/)");
				next if ($curmsg{message} !~ /$sig{$k}{message}/);
				#debug("check() returning syslog $k");
				return($k);
			}
			last TYPE;
		};
		/apache/ && do {
			#FIXME Write apache signature/line comparison
		};
		/windows/ && do {
			#debug("check() type=windows begin");
			my $k;
			foreach $k (keys %sig) {
				#debug("check() foreach k: $k v: $sig{$k}");
				#debug("check() doing: $k if ($sig{$k}{srvname} !~ /$curmsg{srvname}/)");
				#debug("check() doing: $k if ($curmsg{level} !~ /$sig{$k}{level}/)");
				#debug("check() doing: $k if ($curmsg{message} !~ /$sig{$k}{message}/)");
				#FIXME What happens when the signature has an action other than ignore?
				#next if ($sig{$k}{machine} !~ /$curmsg{machine}/);
				next if ($curmsg{srvname} !~ /$sig{$k}{srvname}/);
				next if ($curmsg{level} !~ /$sig{$k}{level}/);
				next if ($curmsg{message} !~ /$sig{$k}{message}/);
				#debug("check() returning windows $k");
				return($k);
			}
		};
	};
	#debug("check() returning anomaly");
	return("anomaly");
}

sub splitmsg {
	my ($type, $line) = @_;
	undef %curmsg;
	$curmsg{full} = "$line";
	$_ = $type;
	TYPE: {
		/syslog/ && do {
			if ($line =~ $cfg{global}{resyslog}) {
				#debug("splitmsg(): re $cfg{global}{resyslog}");
				#debug("splitmsg(): 1:$1 2:$2 3:$3 4:$4");
				$curmsg{type} = "syslog";
				$curmsg{date} = "$1";
				$curmsg{machine} = "$2";
				$curmsg{ps} = "$3";
				$curmsg{message} = $4;
				$curmsg{ps} =~ s/\:$//;
				if ($curmsg{ps} =~ /(\S+)\[(\d+)\]/) {
					$curmsg{ps} = $1;
					$curmsg{pid} = $2;
				} else {
					#$curmsg{ps} = "$3";
					$curmsg{pid} = "0";
				}
				#debug("splitmsg(): resyslog: $curmsg{message}");
				return 0;
			} elsif ($line =~ $cfg{global}{bresyslog}) {
					$curmsg{type} = "syslog";
					$curmsg{date} = "$1";
					$curmsg{machine} = "$2";
					# Hopefully unique identifier for ps to let check() know this line may very well be needing a backup regex
					$curmsg{ps} = "!BA!";
					$curmsg{pid} = "0";
					$curmsg{message} = "$3";
					#debug("splitmsg(): resyslog: $curmsg{message}");
					return 0;
			}
				return 1;
		};
		/apache/ && do {
			if ($line =~ $cfg{global}{reapache}) {
				$curmsg{type} = "apache";
				$curmsg{machine} = "$1";
				$curmsg{user} = "$2";
				$curmsg{message} = "$7";
				$curmsg{protocol} = "$8";
				return 0;
			} else {
				return 1;
			}
		};
		/windows/ && do {
			#FIXME Add windows syslog split support
			if ($line =~ $cfg{global}{rewindows}) {
				$curmsg{type} = "windows";
				$curmsg{date} = "$1";
				$curmsg{machine} = "$2";
				$curmsg{netbios} = "$3";
				$curmsg{level} = "$4";
				$curmsg{srvname} = "$5";
				$curmsg{source} = "$6";
				$curmsg{message} = "$7";
				#debug("splitmsg() type=$curmsg{type} date=$curmsg{date} machine=$curmsg{machine} netbios=$curmsg{netbios} level=$curmsg{level} srvname=$curmsg{srvname} source=$curmsg{source} message=$curmsg{message}");
				return 0;
			} else {
				return 1;
			}
		};
	};
	return 1;
}

# Reads in .conf file
sub readcfg {
	my $conf = shift;
	my ($line,$dir,$cnt);

	open(CONF, "$conf") or die "Can't open conf file: $conf\n";

	while(<CONF>) {
		$cnt++;
		CONF: {
			/^#|\s+#/ && do { last CONF; };
			/^\[(\S+)\]$/ && do { $dir = $1; last CONF; };
			/SyslogRegEx\s+=\s+(\S+)/ && do {
				$cfg{$dir}{resyslog} = "$1";
				#debug("readcfg(): resyslog = $cfg{$dir}{resyslog}");
				die "Error in $conf, line $cnt: Syslog Regular Expression provided does not match a standard syslog line\n" unless (checkre("syslog", "$cfg{$dir}{resyslog}") == 1);
				last CONF;
			};
			/SyslogRegExBackup\s+=\s+(\S+)/ && do {
				$cfg{$dir}{bresyslog} = "$1";
				die "Error in $conf, line $cnt: Backup Syslog Regular Expression provided does not match a standard syslog line\n" unless (checkre("bsyslog", "$cfg{$dir}{bresyslog}") == 1);
				last CONF;
			};

			/LogFile\s+=\s+(\S+)/i && do {
				$cfg{$dir}{file} = $1;
				if (!-f $cfg{$dir}{file}) {
					die "Error in $conf, line $cnt: '$cfg{$dir}{file}' does not exist.\n";
				}
				last CONF;
			};
			/AnomalyRcpts\s+=(.*)$/i && do {
				my $emails = $1;
				$cfg{$dir}{rcpts} = $emails;
				die "Error in $conf, line $cnt: No valid email address(es) '$cfg{$dir}{rcpts}'.\n" unless ($cfg{$dir}{rcpts} =~ /\S+\@\S+/);
				last CONF;
			};
			/AnomalyOutfile\s+=\s+(\S+)/ && do {
				$cfg{$dir}{outfile} = $1;
				last CONF;
			};
			/LogType\s+=\s+(\w+)/i && do {
				$cfg{$dir}{type} = $1;
				die "Error in $conf, line $cnt: Invalid log type '$cfg{$dir}{type}.\n" unless ($cfg{$dir}{type} eq "syslog");
				last CONF;
			};
			/SignatureFile\s+=\s+(\S+)/ && do {
				$cfg{$dir}{signature} = $1;
				if (!-f $cfg{$dir}{signature}) {
					die "Error in $conf, line $cnt: '$cfg{$dir}{signature}' does not exist.\n";
				}
				last CONF;
			};
			/FormCard\s+=\s+(\w+)/ && do {
				$cfg{$dir}{card} = $1;
				if ($cfg{$dir}{card} =~ /y|yes/i) {
					$cfg{$dir}{card} = 1;
				} else {
					$cfg{$dir}{card} = 0;
				}
				last CONF;
			};
			/AnomalyAction\s+=\s+(.*)$/i && do {
				$cfg{$dir}{anomaly} = $1;
				last CONF;
			};
			/MailServer\s+=\s+(\S+)/i && do {
				$cfg{$dir}{mailserv} = $1;
				last CONF;
			};
			/MessageSubject\s+=\s(.*)$/i && do {
				$cfg{$dir}{subject} = $1;
				last CONF;
			};
			/MessageSubjectForQueues\s+=\s(.*)$/i && do {
				$cfg{$dir}{qsubject} = $1;
				last CONF;
			};

			/MessageSubjectLimit\s+=\s+(\d+)$/i && do {
				$cfg{$dir}{sublimit} = $1;
				last CONF;
			};
			/MessageSubjectIPResolve\s+=\s+(\w+)/ && do {
				$cfg{$dir}{subresolve} = $1;
				if ($cfg{$dir}{subresolve} =~ /y|yes/i) {
					$cfg{$dir}{subresolve} = 1;
				} else {
					$cfg{$dir}{subresolve} = 0;
				}
				last CONF;
			};
			/MessageSuggestSignature\s+=\s+(\w+)/ && do {
				$cfg{$dir}{suggest} = $1;
				if ($cfg{$dir}{suggest} =~ /y|yes/i) {
					$cfg{$dir}{suggest} = 1;
				} else {
					$cfg{$dir}{suggest} = 0;
				}
				last CONF;
			};
			/WildcardSuggestedSignature\s+=\s+(\w+)/ && do {
				$cfg{$dir}{wcsuggest} = $1;
				if ($cfg{$dir}{wcsuggest} =~ /y|yes/i) {
					$cfg{$dir}{wcsuggest} = 1;
				} else {
					$cfg{$dir}{wcsuggest} = 0;
				}
				last CONF;
			};
			/SuggestedSignatureLocation\s+=\s+(\S+)/ && do {
				$cfg{$dir}{suggestloc} = $1;
				last CONF;
			};
			/MailFrom\s+=\s(.*)$/i && do {
				$cfg{$dir}{from} = $1;
				last CONF;
			};
			/ExitOnStart\s+=\s+(\w+)$/i && do {
				if ($1 =~ /^y/i) {
					die "It is very important to read, understand and configure each option in $conf\nPlease go back and read $conf in it's entirety.  Thank you.\n";
				}
			};
			/QueueMail\s+=\s+(\w+)$/i && do {
				$cfg{$dir}{qmail} = $1;
				if ($cfg{$dir}{qmail} =~ /y|yes/i) {
					$cfg{$dir}{qmail} = 1;
				} else {
					$cfg{$dir}{qmail} = 0;
				}
				last CONF;
			};
			/QueueDumpTimeThreshold\s+=\s+(\d+)$/i && do {
				$cfg{$dir}{qthresh} = $1;
				last CONF;
			};
		};
	}
}

# Forms the pretty log card
sub mkcard {
	my ($type, $dir) = @_;
	#debug("mkcard() start, type='$type', dir='$dir'");
	my @arr;
	my $k = 'alert';
	$_ = $type;
	TYPE: {
		/syslog/ && do {
			my ($i, $tmpalert);
			my $max = (length($k) + length($curmsg{machine}));
			my $spc = "";
			for $i (0 .. $max) {$spc .= "-";}
			push(@arr, "\n,-$spc-.\n");
			push(@arr, "| $k\@$curmsg{machine} |\n");
	# Display some stats about the running processes
			if ($max < length($tmpalert)) { $max = length($tmpalert); }
			if ($max < (length($curmsg{date}) + 10)) { $max = (length($curmsg{date}) + 10); }
			if ($max < (length($curmsg{machine}) + 10)) { $max = (length($curmsg{machine}) + 10); }
			if ($max < (length($curmsg{ps}) + 10)) { $max = (length($curmsg{ps}) + 10); }
			$spc = "";
			for $i (0 .. $max) {$spc .= "-";}
			push(@arr, "|-$spc.\n");
			$spc = "";
			for $i (1 .. $max - length($curmsg{date}) - 10) {$spc .= " ";}
			push(@arr, "|    Date: $curmsg{date}$spc  |\n");
			$spc = "";
			for $i (1 .. $max - length($curmsg{machine}) - 10) {$spc .= " ";}
			push(@arr, "|    Host: $curmsg{machine}$spc  |\n");
			$spc = "";
			for $i (1 .. $max - length($curmsg{ps}) - 10) {$spc .= " ";}
			push(@arr, "| Process: $curmsg{ps}$spc  |\n");
			$spc = "";
			for $i (0 .. $max) {$spc .= "-";}
			push(@arr, "|-$spc'\n");
			#debug("mkcard(): $curmsg{message}");
			push(@arr, "| Message: $curmsg{message}\n");
			push(@arr, "`--- --  -     -\n");
			return(@arr);
		};
		/apache/ && do {
			#FIXME Write apache alert card formation
		};
		/windows/ && do {
			#FIXME Write windows alert card formation
			push(@arr, "$curmsg{full}");
			return(@arr);
		};
	};
	print "no card made\n" unless $cfg{$dir}{quiet} == 1;
}

# Adds log to present mail queue
sub mailaddqueue {
	my (@sugsig) = @_;
	#debug("mailaddqueue() start CURMSGMACHINE: $curmsg{machine}");
	# The following 3 lines keep a record of the last message queued
	$lastmsgqueue{message} = "$curmsg{message}";
	$lastmsgqueue{ps} = "$curmsg{ps}";
	$lastmsgqueue{machine} = "$curmsg{machine}";
	$mailqueue{total}++;

	push(@{$mailqueue{hosts}}, "$curmsg{machine}");

	$mailqueue{head} = "$curmsg{full}\n$mailqueue{head}";
	$mailqueue{message} = "@sugsig\n$mailqueue{message}";

	#debug("mailaddqueue(): hosts=$mailqueue{hosts} head=$mailqueue{head} message=$mailqueue{message} total=$mailqueue{total}");
}

sub mailsend {
	my ($from, $to, $subject, $sublimit, $resolve, @message) = @_;
	#debug("mailsend() start");
	#debug("mailsend() from: $from to: $to sub: $subject data: @message");
	my $hname;

	if ($subject =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/ && $resolve == 1) {
		my $ip = $1;
		my $iaddr = inet_aton("$ip");
		my $host = gethostbyaddr($iaddr, AF_INET);
		if ($host =~ /\S+/) {
			$hname = "($host)";
			$subject =~ s/$ip/$ip $hname/;
		}
	}

	$subject = substr($subject, 0, $sublimit);

	%mail = (
		Smtp    => "$cfg{global}{mailserv}",
		To      => "$to",
		From    => "$from",
		Subject => "$subject",
		'X-Mailer' => "Mail::Sendmail version $Mail::Sendmail::VERSION",
		Message => "@message",
	);
  sendmail(%mail) or print STDERR "$Mail::Sendmail::error\n";
	#debug("mailsend() finished");
}

sub trsubject {
	my $subject = $_[0];
	#debug("trsubject() lastmsgqueue{machine}: $lastmsgqueue{machine} - subject: $subject");
	$subject =~ s/\*H/$lastmsgqueue{machine}/g;
	$subject =~ s/\*M/$lastmsgqueue{message}/g;
	$subject =~ s/\*P/$lastmsgqueue{ps}/g;
	return("$subject");
}

sub qtrsubject {
	my $s = $_[0];
	#debug("qtrsubject(): pre subject=$s");
	my %ins;
	my @hosts;
	foreach my $foo (@{$mailqueue{hosts}}) {
		push(@hosts, $foo) unless $ins{$foo}++;
	}
	$s =~ s/\*H/@hosts/g;
	$s =~ s/\*T/$mailqueue{total}/g;
	#debug("qtrsubject(): post subject=$s");
	return("$s");
}

sub checkre {
	my ($type, $re) = @_;
	$_ = $re;
	if ($type eq "syslog" && "Feb 21 16:20:42 host process[31337]: sample syslog message" =~ /$re/) {
		return(1);
	} elsif ($type eq "bsyslog" && "May  3 10:20:18 host 201623 05/03/2005 10:20:18.170 SEV=4 AUTH/22 RPT=4978  User [127.0.0.1] Group [127.0.0.1] connected, Session Type:IPSec/LAN-to-LAN" =~ /$re/) {
		return(1);
	}
	return(0);
}

# Generates valid regex for suggested signature
sub genregexp {
	my $line = $_[0];
	chomp($line);
	my ($regexp, @split, $foo);
	@split = split(/\s+/, $line);
	foreach $foo (@split) {
		$_ = $foo;
		SWITCH: {
			/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ && do {
				$regexp .= "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}";
				last SWITCH;
			};
			/^\S+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\S+$/ && do {
				$regexp .= "\\S+\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\S+";
				last SWITCH;
			};
			/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\S+$/ && do {
				$regexp .= "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\S+";
				last SWITCH;
			};
			/^\W+$/ && do {
				$regexp .= "\\S+";
				last SWITCH;
			};
			/^\d+$/ && do {
				$regexp .= "\\d+";
				last SWITCH;
			};
			/^\w+$/ && do {
				$regexp .= "$foo";
				last SWITCH;
			};
			/^\S+$/ && do {
				$regexp .= "\\S+";
				last SWITCH;
			};
			next;
		};
		$regexp .= "\\s+";
	}
  chop($regexp);chop($regexp);chop($regexp);
  return($regexp);
}

sub printhelp {
	print "Usage: ./devialog.pl <-c conf> [-hd]
	-c	Specify config, default uses ./devialog.conf
	-d	Debug
	-h	This help
";
}

sub debug {
	my $msg = $_[0];
	if ($opts{d} == 1) {
		print "debug: $msg\n";
	}
}
