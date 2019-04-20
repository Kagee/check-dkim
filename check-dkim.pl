#!/usr/bin/env perl
use utf8;
binmode(STDOUT, ":utf8");
use Modern::Perl '2015';
use autodie;

my $LOG_NAME = "check-dkim";

use Sys::Syslog qw(:standard :macros);

BEGIN {
    openlog($LOG_NAME, "ndelay,pid", "local0") or die("$LOG_NAME: Critical error, failed to connect to syslog");
    $SIG{'__WARN__'} = sub {
        syslog(LOG_WARNING, @_);
        warn @_
    };
    $SIG{'__DIE__'} = sub {
        syslog(LOG_ERR, @_);
        die @_
    };
}
END {closelog();}

use Fcntl; # O_RDONLY
use Cwd;
#use Redis;
use Email::MIME;
use Mail::DKIM::Verifier;
use JSON;
use Email::Address::List;
use List::Util qw(uniq);

my $dkim_obj = Mail::DKIM::Verifier->new();
my $message;

# This will read (and/or) STDIN and first command line argument
while (<>) {
    # Email::Mime
    $message .= $_;

    # Mail::Dkim::Verifier
    # remove local line terminators
    chomp;
    s/\015$//;
    # use SMTP line terminators
    $dkim_obj->PRINT("$_\015\012");
}

die("Message was not filled from stdin or file, dies") unless ($message);

$dkim_obj->CLOSE;

sub get_dkim_data {
    my $dkim_obj = shift;
    my %data;
    $data{result} = $dkim_obj->result;
    $data{result_full} = $dkim_obj->result_detail;

    # there might be multiple signatures, what is the result per signature?
    #foreach my $signature ($dkim_obj->signatures)
    #{
    #    print "\t\tsignature identity: " . $signature->identity . ', verify result: ' . $signature->result_detail . "\n";
    #}

    # the alleged author of the email may specify how to handle email
    #print Dumper($dkim_obj->policies);
    #foreach my $policy ($dkim_obj->policies)
    #{
    # https://metacpan.org/pod/Mail::DKIM::DkimPolicy
    # Mail::DKIM::DkPolicy
    # Mail::DKIM::AuthorDomainPolicy
    #    print $policy->location();
    #    print ("Policy: " . $policy->apply($dkim_obj) . "\n");
    #    print "\t\tWARNING: fraudulent message" if ($policy->apply($dkim_obj) eq 'reject');
    #}

    return \%data;
}

sub get_email_data {
    my $message = shift;
    my %data;
    my $email_obj = Email::MIME->new($message);
    my $header_obj = $email_obj->header_obj;
    $data{"DKIM-Signature"} = $header_obj->header_raw("DKIM-Signature");

    $data{"To"} = ();
    $data{"To"}{"raw"} = $header_obj->header_raw("to");
    my @tos = Email::Address::List->parse(
        $header_obj->header_raw("to"),
        skip_comments => 1,
        skip_groups   => 1,
        skip_unknown  => 1
    );
    foreach my $e (@tos) {
        if ($e->{'type'} eq 'mailbox') {
            $data{"To"}{"host"} = $e->{'value'}->host;
            $data{"To"}{"mailbox"} = $e->{'value'}->user;
            (my $user, my $uuid) = split /\+/, $e->{'value'}->user;
            $data{"To"}{"uuid"} = $uuid;
            $data{"To"}{"user"} = $user;
        }
    } #$data{"To_parsed"} = @tos;

    #my @parts = $email->parts; # These will be Email::MIME objects, too.
    #my $decoded = $email->body;
    #my $non_decoded = $email->body_raw;

    #my $content_type = $email->content_type;
    #my $description = $email->debug_structure;

    #$description =~  s/^/\t\t/g;
    #$description =~  s/\n/\n\t\t/g;
    #$description =~  s/^ *\+/\t\t/g;
    #$description =~  s/^ ? *\+/\t\t\t/gm;
    #chomp $description;

    #print "\tcontent_type: " . $content_type . "\n";
    #print "\temail structure:\n" . $description . "\n";


    return \%data;
}

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
            return uniq split /:/, $tagdata;
        }
    }
}

my %email_data;

$email_data{"DKIM"} = get_dkim_data $dkim_obj;
$email_data{"EMAIL"} = get_email_data $message;

my $email_data_json = to_json(\%email_data, { pretty => 1 });

say $email_data_json;

print("-----------------------------------------------------------------------\n");
