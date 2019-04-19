#!/usr/bin/env perl
use utf8;
binmode(STDOUT, ":utf8");
use Modern::Perl '2015';
use autodie;

my $LOG_NAME = "check-dkim";

use Sys::Syslog qw(:standard :macros);

BEGIN {
    openlog($LOG_NAME, "ndelay,pid", "local0") or die("$LOG_NAME: Critical error, failed to connect to syslog");
    $SIG{'__WARN__'} = sub { syslog( LOG_WARNING, @_ ); warn @_ };
    $SIG{'__DIE__'}  = sub { syslog( LOG_ERR, @_ ); die @_ };
}
END { closelog(); }

use Fcntl; # O_RDONLY

use Cwd;

#use Redis;

use Email::MIME;

use Mail::DKIM::Verifier;

use JSON;




my $dkim_obj = Mail::DKIM::Verifier->new();
my $message;

{
    no warnings 'once';
    my $inputfile = "data/facebook2.eml";
    open(my $EMAIL_HANDLE, "<", $inputfile) or do {
        my $error = "Failed to open inputfile for reading: ". $inputfile;
        #syslog(LOG_ERR|LOG_LOCAL6, "Failed to open inputfile for reading: ". $inputfile);
        die($error);
    };

     syslog('info', '%s', 'this is another test');
    syslog('mail|warning', 'this is a better test: %d', time);
    closelog();


    #while (<STDIN>)
    while (<$EMAIL_HANDLE>) {
        $message .= $_;
        # remove local line terminators
        chomp;
        s/\015$//;

        # use SMTP line terminators
        $dkim_obj->PRINT("$_\015\012");
    }
    close($EMAIL_HANDLE) or die("Failed to close?");
}
$dkim_obj->CLOSE;

my $result = $dkim_obj->result;

print("DKMIM:");
print("\ttesult: " . $result . "\n");

if ($result ne "pass") {
    my $detail = $dkim_obj->result_detail;
    print("\t\tresult details: " . $detail . "\n");
}
# there might be multiple signatures, what is the result per signature?
foreach my $signature ($dkim_obj->signatures)
{
    print "\t\tsignature identity: " . $signature->identity . ', verify result: ' . $signature->result_detail . "\n";
}

# the alleged author of the email may specify how to handle email
foreach my $policy ($dkim_obj->policies)
{
    #print ("Policy: " . $policy);
    print "\t\tWARNING: fraudulent message" if ($policy->apply($dkim_obj) eq 'reject');
}
print("Email headers:\n");
my $email = Email::MIME->new($message);

my @parts = $email->parts; # These will be Email::MIME objects, too.
my $decoded = $email->body;
my $non_decoded = $email->body_raw;

my $content_type = $email->content_type;
my $description = $email->debug_structure;

#$description =~  s/^/\t\t/g;
#$description =~  s/\n/\n\t\t/g;
$description =~  s/^ *\+/\t\t/g;
$description =~  s/^ ? *\+/\t\t\t/gm;
chomp $description;

print "\tcontent_type: " . $content_type . "\n";
print "\temail structure:\n" . $description . "\n";

sub get_dkim_signed_headers {
    my ($header_obj) = @_;
    my $dkim_sig = $header_obj->header_raw("DKIM-Signature");
    return 0 if (not $dkim_sig);
    my @parts = split /; /, $dkim_sig;
    foreach my $part (@parts) {
        chomp $part;
        my @tag = split /=/, $part;
        if ($tag[0] eq "h") {
            my $tagdata = $tag[1];
            return split /:/, $tagdata;
        }
    }
}

#my @pairs = $parsed->header_str_pairs;
my $header = $email->header_obj;
use Data::Dumper;

# DKIM-Signature h=Date:To:Subject:From:MIME-Version:Content-Type;

#print $header->as_string;
my @vhead = get_dkim_signed_headers($header);

foreach my $hname (@vhead) {
    my $hdata = $header->header_str($hname);
    print "VALIDATED: " . $hname . ": " . $hdata . "\n" if $hdata;
}


print("\n\n-----------------------------------------------------------------------\n");
