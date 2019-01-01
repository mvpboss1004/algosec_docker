package FwaLic;

#
# License verification module
#
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
#         Do not edit!
# This file gets patched to set the signing key ID.
# Edit the template file and run the makefile instead.
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ 
#

use strict;
use Carp;
use File::Basename;
use FwaUser;
use POSIX ":sys_wait_h";
use URI::Escape;
use domains_mng;
use Logger;
use FwaUtil;
# do not remove - needed by perl2exe
#perl2exe_include Carp/Heavy

my $logger = new Logger();

############ flexlm disabled ###########
# everything is the same, license format stays the same,
# but it's not signed any more.
#
# to re-enable, set $FLEXLM_ACTIVE = 1
my $FLEXLM_ACTIVE=1;

# variable for license trouble error message file
my $license_trouble_file = $ENV{FIRMATO_DIR} . "/data/license-trouble.txt";
# variable to get the fa-version used
my $fa_version_file = $ENV{FIRMATO_DIR} . "/data/fa-version";
my $fireFlow_version_file_old = "/opt/rt3/local/etc/fireflow_version";
my $fireFlow_version_file = "/usr/share/fireflow/local/etc/fireflow_version";

############ [AW 5 Dec 2003] CGI-bin support disabled: 
# stop using sudo to issue commands as the user "firmato"
# instead just issue the commands as usual.
# this will break the web server distribution but will
# work fine from the command line
#
my $USE_SUDO=0;

BEGIN {
    use Exporter   ();
    use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS %md5sig);
    $VERSION = do { my @r = (q$Revision: 1.91 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r }; # must be all one line, for MakeMaker
    @ISA         = qw(Exporter);
    @EXPORT      = ( );
    %EXPORT_TAGS = ( 
		     all => [ qw!&get_lic_params &get_lic_params_inside_analysis %lic_parms &count_reports &check_online_license &get_activation_license $is_risk_allowed $is_optimize_allowed $is_auto_impl_allowed $is_fireflow_allowed $is_migration_allowed $is_basicCompliance_allowed! ],
		     license => [ qw!&get_lic_params &get_lic_params_inside_analysis %lic_parms &get_activation_license $is_risk_allowed $is_optimize_allowed $is_auto_impl_allowed $is_fireflow_allowed $is_migration_allowed $is_basicCompliance_allowed! ],#D.R added: $is_old_lic_ver, $is_risk_allowed, $is_optimize_allowed, $is_fireflow_allowed $is_migration_allowed
		     );
    %md5sig = ( fa_usage => '1d425847d2e21022e5ab8949dabbdda9',
	    );
    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw(&get_lic_params &get_lic_params_inside_analysis %lic_parms &count_reports &check_online_license &get_activation_license $is_risk_allowed $is_optimize_allowed $is_auto_impl_allowed $is_fireflow_allowed $is_migration_allowed $is_basicCompliance_allowed);
}
use vars @EXPORT_OK;

# Local non-exported variables
# %md5sig       : hash of signatures, specified during build
# $debug        : debug flag, usu. from $ENV{DEBUG}
# $error_msg    : error message describing last failure
# $error_status : OS error code if last failure was an external program call
use vars qw($flexlmrc $debug $error_msg $error_status);

#OS files
my $SuSE_REL_FILE      = "/etc/SuSE-release";
my $REDHAT_REL_FILE      = "/etc/redhat-release";

INIT { 
    $flexlmrc = "$ENV{HOME}/.flexlmrc";
    if ( $ENV{DEBUG} )
    {
        $debug = 1;
    }
    else
    {
        $debug = 0;
    }
}

#-------------------------------------------
# 1. validate that the fa_usage  program is untampered with
# 2. run fa_usage to validate the license file and extract the parameters 
# 3. fill %lic_parms with the values
#
sub get_lic_params
{
	my ($meta_dir, $license_file_name) = @_;
	if ($meta_dir) {
		FwaUtil::meta_dir($meta_dir);
	}
    my $cmd_name = 'fa_usage';
    my @lic_output;
    undef %lic_parms;
    my $line;
    my ($key, $val);
    my $lic_param;
    
    FwaUser::read_config();
    my $run_as = ""; 
    if (defined $FwaUser::conf_hash{'Run_As_License'}){
		 $run_as  = $FwaUser::conf_hash{'Run_As_License'};
    }
    # check if defined a license file name (= it was sent) 
    # then we will send it to fa_usage with -v to check 
    # that given license file name is valid
    if (defined $license_file_name) 
    {
    	$lic_param = "-v $license_file_name";
    }
    # otherwise just use -t and fa_usage will use the license file from /var/opt/fa
    else
    {
    	$lic_param = '-t';
    	$license_file_name = "/var/opt/fa/fwa.lic" #D.R 
    }
            
    #set http_proxy if defined in config file
    FwaUser::identify_user();
    FwaUser::set_proxy();


    if ($FLEXLM_ACTIVE)
    {
        #
        # find the testlic command
        #
    	my $fa_usage = find_cmd($cmd_name);
		if (!defined $fa_usage || $fa_usage eq "") {
           	$logger->print_log("Error", Logger::PROG_MESSAGE, "Could not find usage script");
			return undef;
		}
        # validate the md5 hash of fa_usage
		if (!validate_cmd($cmd_name,$fa_usage)) {
           	$logger->print_log("Error", Logger::PROG_MESSAGE, "Licensing mechanism code failed validation - file may have been tampered with");
			return undef;
		}
 
        #
        # get rid of the .flexlmrc file if it exists
        #
        if (-f $flexlmrc)
        {
            system('rm', '-f', "$flexlmrc");
        }
        # get the license data
		$logger->print_log("Debug", Logger::PROG_MESSAGE, "Running: $fa_usage with $lic_param");
 
        @lic_output = run_cmd($fa_usage,$lic_param, '2>&1');
        
		$logger->print_log("Debug", Logger::PROG_MESSAGE, "fa_usage output: @lic_output\n");

        if ((!@lic_output) or ($lic_output[0] eq ''))
        {
			$logger->print_log("Info", Logger::PROG_MESSAGE, "No output for command: $fa_usage $lic_param");
            return undef;
        }
    # parse the license
    }
    else
    { 
        # fake it - we still want to know the license type
        # 
        ### my $licline = `grep VENDOR_STRING $lic_filename`;
        my $lic_filename = "$ENV{FIRMATO_DIR}/ops/fwa.lic";
        my $licline = run_cmd('grep', "VENDOR_STRING $lic_filename");
        my $lictype;
        ($lictype) = $licline =~ /VENDOR_STRING=([^\s]*) /;
        # 7.1 is the license version starting afa 6.6
        $lic_output[0] = "License_version=7.1";
        $lic_output[1] = "License_id=7.1";
        $lic_output[2] = "Issued_on=1-Jan-2000";
        $lic_output[3] = "Expires_on=1-jan-0";
        $lic_output[4] = "Issued_by=lumeta";
        $lic_output[5] = "Vendor_string=$lictype"; 
        $lic_output[6] = "Modules_=Core"; #D.R - Core is default. Holds string in format <feature1>;<feature2> etc
    }
    parse_license(@lic_output);
    # If we are in domain, will update %lic_parms with domain's features (if valid)
    my $rc = updateDomainFeatures(\%lic_parms);
    if($rc == -1){
        return undef;
    }



	$is_risk_allowed = 0;
	$is_optimize_allowed = 0;
	$is_fireflow_allowed = 0; #support for FireFlow product
	$is_migration_allowed = 0;#New for Migration product
	$is_auto_impl_allowed = 0;
	$is_basicCompliance_allowed = 0;
	
	#D.R Important - backward compatibility with old license
	if ( $FwaLic::lic_parms{'License_version'} eq "1.0")	{
		$is_optimize_allowed = 1;
		$is_risk_allowed = 1;
		$is_migration_allowed = 1;
		return 1;
	}
		   
    my $feat_str=$FwaLic::lic_parms{'Modules_'}; 
	    	
   	if (defined $feat_str){
	   	if ($feat_str =~ /Optimization/){
	 	  	$is_optimize_allowed = 1; 	
	   	}
	    if ($feat_str =~ /Risk/){
	    	$is_risk_allowed = 1;
	    }
	    elsif ($feat_str =~ /BasicCompliance/){
			$is_basicCompliance_allowed = 1;
		}
	    if ($feat_str =~ /FireFlow/){
	    	$is_fireflow_allowed = 1;
	    }
	    if ($feat_str =~ /Migration/){
	    	$is_migration_allowed = 1;
	    }
	    if ($feat_str =~ /ActiveChange/){
	    	$is_auto_impl_allowed = 1;
	    }
	}
	# checking the Run_As_License config parameter that runs over 
	# the existing license (only reduce it) 
	if ($run_as ne ""){
		$logger->print_log("Info", Logger::PROG_MESSAGE, "Run_As_License parameter found: $run_as");
		if ($run_as !~ /Optimization/ && $is_optimize_allowed) {
			$is_optimize_allowed = 0;
			$logger->print_log("Info", Logger::PROG_MESSAGE, "Forcing Optimization module to be off");
		}
		if ($run_as !~ /Risk/ && $is_risk_allowed) {
			$is_risk_allowed = 0;
			$logger->print_log("Info", Logger::PROG_MESSAGE, "Forcing Risk module to be off");
		}
		if ($run_as !~ /FireFlow/ && $is_fireflow_allowed) {
			$is_fireflow_allowed = 0;
			$logger->print_log("Info", Logger::PROG_MESSAGE, "Forcing FireFlow module to be off");
		}		
	}
 
 	FwaUtil::read_meta_file();
 	if (not defined $FwaUtil::fwa_meta{"Lic_Features"}) {
	 	my @meta_params = ();	
	 	if ($is_risk_allowed) {
	 		push @meta_params, "Risk";
	 	}
 		if ($is_optimize_allowed) {
 			push @meta_params, "Optimization";
 		}
 		if ($is_basicCompliance_allowed) {
 			push @meta_params, "BasicCompliance";
 		}
 		if ($is_migration_allowed) {
 			push @meta_params, "Migration";
 		}
 		if ($is_auto_impl_allowed) {
 			push @meta_params, "ActiveChange";
 		}
 		if ($is_fireflow_allowed) {
 			push @meta_params, "FireFlow";
 		}
 		FwaUtil::write_meta("Lic_Features", join(";", @meta_params));
 	}
 	if (not defined $FwaUtil::fwa_meta{"Lic_Parms"}) {
 		
 		FwaUtil::write_meta("Lic_Parms", join(",", map {$_.":".$FwaLic::lic_parms{$_}} keys %FwaLic::lic_parms));
 	}
    
    PrintLicDebugInfo();
    return 1;
}

sub get_lic_params_inside_analysis
{

	$is_risk_allowed = 0;
	$is_optimize_allowed = 0;
	$is_fireflow_allowed = 0; #support for FireFlow product
	$is_migration_allowed = 0;#New for Migration product
	$is_auto_impl_allowed = 0;
	$is_basicCompliance_allowed = 0;

	#D.R Important - backward compatibility with old license
	if ( exists ($FwaLic::lic_parms{'License_version'}) && $FwaLic::lic_parms{'License_version'} eq "1.0")	{
		$is_optimize_allowed = 1;
		$is_risk_allowed = 1;
		$is_migration_allowed = 1;
		return 1;
	}
	
	my $meta_dir = shift;
	if ($meta_dir) {
		FwaUtil::meta_dir($meta_dir);
	}
	
	my $force_main_config = 1;
	FwaUser::read_config($force_main_config);
	
	# If we are not in distributed setting - use regular licensing
	use DistUtilMini;
	use DistGlobals;
	if (!exists ($FwaUser::conf_hash{"Is_Distribution_Enabled"}) || $FwaUser::conf_hash{"Is_Distribution_Enabled"} ne 'yes' 
		||  ($FwaUser::conf_hash{"Is_Distribution_Enabled"} eq 'yes' && DistUtilMini::Get_Dist_Elem_Type() eq DistGlobals::TYPE_MASTER)) 
	{
		return get_lic_params();
	}
	
	$logger->print_log("Info", Logger::PROG_MESSAGE, "get_lic_params: running from meta file");
	
	# If this is the slave - use the parameters from fwa.meta because we cannot use the current license.
	FwaUtil::read_meta_file();
	my $feat_str = $FwaUtil::fwa_meta{"Lic_Features"};
	if (not defined $feat_str || $feat_str eq "") {
		$error_msg = "get_lic_params_inside_analysis found no Lic_Features value if meta file";
		return 0;
	}
	if ($feat_str =~ /Optimization/){
 	  	$is_optimize_allowed = 1; 	
   	}
    if ($feat_str =~ /Risk/){
    	$is_risk_allowed = 1;
    }
    elsif ($feat_str =~ /BasicCompliance/){
		$is_basicCompliance_allowed = 1;
	}
    if ($feat_str =~ /FireFlow/){
    	$is_fireflow_allowed = 1;
    }
    if ($feat_str =~ /Migration/){
	   	$is_migration_allowed = 1;
    }
    if ($feat_str =~ /ActiveChange/){
    	$is_auto_impl_allowed = 1;
    }
    my $params_str = $FwaUtil::fwa_meta{"Lic_Parms"};
    if (not defined $params_str || $params_str eq "") {
		$error_msg = "get_lic_params_inside_analysis found no Lic_Parms value if meta file";
		return 0;
	}
	my @params = split ",", $params_str;
	foreach my $param (@params) {
		my ($key, $val) = split ":", $param;
		next if (not defined $key || $key eq "");		
		$FwaLic::lic_parms{$key} = $val;
	}

    PrintLicDebugInfo();
    return 1;
}


#-----------------------------------------------
sub count_reports
{
    my $mode = shift;
    my $args;
    my $count_output;

    carp "Counting reports in $mode mode" if ($debug > 0);

    my $TMPFILE;
    my $params;
    my @rc;
    my $cmd = "fa_usage";
    my $exec_cmd;
    

    $TMPFILE=`mktemp /tmp/fa_XXXXXX`;
    chomp($TMPFILE);

    $params = sprintf("-d %s", $TMPFILE);
    
    my $fa_cmd = find_cmd($cmd);
    return undef unless $fa_cmd;
# validate fa_usage command
    return undef unless validate_cmd($cmd, $fa_cmd);

#run fa_usage command
    
    @rc = run_cmd($cmd, $params);
    if (@rc != 0)
    {
        carp print "fa_usage returned @rc" if($debug);
        return undef
    }
#   return undef unless @rc;
   
    $count_output =`grep Job_status=COMPLETED $TMPFILE | wc -l`;
    chomp($count_output);

    unlink $TMPFILE;
    if(!($mode =~ "quiet"))
    {
        printf "%d\n", $count_output;
    }
    return $count_output;
}

# Input: none
# Output: \%totalFirewallsPerDomain - ref to a hash of the type: $totalFirewallsPerDomain{$domain id} = number of unique firewalls
#	used per domain.
#         \%totalRoutersPerDomain - ref to a hash of the type: $totalRoutersPerDomain{$domain id} = number of unique routers
#   used per domain.
sub returnTotalUsagePerDomain
{
    $logger->print_log("Info", Logger::PROG_MESSAGE, "Stating returnTotalUsagePerDomain");
    my $fw_key = undef;
    my $returnTotalUsagePerDomain = 1;

    # We would not use the output hash $fw_usage, only $fw_usage_per_domain
    my ($rc, $fw_usage, $fw_usage_per_domain, $router_usage, $router_usage_per_domain) = countFirewallsUsageToHash($fw_key, $returnTotalUsagePerDomain);

    my %totalFirewallsPerDomain;
    my %totalRoutersPerDomain;
    if($rc && defined $fw_usage_per_domain && ref $fw_usage_per_domain eq "HASH" && defined $router_usage_per_domain && ref $router_usage_per_domain eq "HASH"){
        foreach my $domain (keys %{$fw_usage_per_domain}){
            $totalFirewallsPerDomain{$domain} = scalar (keys %{$fw_usage_per_domain->{$domain}});
        }
        foreach my $domain (keys %{$router_usage_per_domain}){
            $totalRoutersPerDomain{$domain} = scalar (keys %{$router_usage_per_domain->{$domain}});
        }
    }
    return (\%totalFirewallsPerDomain, \%totalRoutersPerDomain);
}

sub get_current_domain_id
{
    if(domains_mng::is_logged_into_domain()){
        return domains_mng::get_current_domain_id();
    }
    return undef;
}

# Input: $mode=quite/verbose. If verbose (currently not in use) print usage for each firewall (and each domain if exist domains).
#   $fw_key - if exists, raise the firewall count of $fw_key by one (firewall key can be ip address based on <brand>2urt calculation or tree name).
# Output: ($firewall_count, $router_count, $lic_exceeded):
#   $firewall_count - number of firewalls in use (if we are in domain, return the use of the specific domain)
#   $router_count - number of routers in use (if we are in domain, return the use of the specific domain)
#   $lic_exceeded  - 1 if the usage is greater than the quota (if we are in domain, we check it for the specific domain)
sub checkLicFwUsageAndExceeded
{
    my ($mode, $fw_key, $job_dir) = @_;

    $logger->print_log("Debug", Logger::PROG_MESSAGE, "Stating checkLicFwUsageAndExceeded mode [$mode] device license id [$fw_key]");
        
    my $currentDomainID = get_current_domain_id();
    my $returnTotalUsagePerDomain = (defined $currentDomainID) ? 1 : 0;
    # If we are in a domain, send returnTotalUsagePerDomain=1 to countFirewallsUsageToHash. This will return $fw_usage_per_domain as well,
    #   which is a ref to a hash of this format: {domain id}{firewalls key} = usage of each firewall (number of reports).
    my ($rc, $fw_usage, $fw_usage_per_domain, $router_usage, $router_usage_per_domain) = countFirewallsUsageToHash($fw_key, $returnTotalUsagePerDomain, $job_dir);
    # $rc=1 on success, 0 otherwise
    if (!$rc || !defined $fw_usage || ref $fw_usage ne "HASH" || !defined $router_usage || ref $router_usage ne "HASH"){
        $logger->print_log("Error", Logger::PROG_MESSAGE, "countFirewallsUsageToHash failed");
        return undef; 
    }

    $logger->print_log("Debug", Logger::PROG_MESSAGE, "currentDomainID [$currentDomainID]");
    # fw_usage: $fw_usage{firewall id} = usage (global, not per domain).
    my $firewall_count = keys %{$fw_usage};
    my $router_count = keys %{$router_usage};
    my $firewall_quota = $FwaLic::lic_parms{'Firewalls_quota'};
    my $router_quota = $FwaLic::lic_parms{'Routers_quota'};
    $logger->print_log("Info", Logger::PROG_MESSAGE, "Global license firewall_count[$firewall_count] firewall_quota[$firewall_quota] router_count[$router_count] router_quota[$router_quota]");
    # First check if global license exceeded
    my $lic_exceeded = isExceeded($firewall_count, $firewall_quota, $router_count, $router_quota);
    my $domainStr = "";
    if($lic_exceeded){
        $logger->print_log("Info", Logger::PROG_MESSAGE, "Global license exceeded");
    }else{
        # If global license did not exceed, check domain license
        if(defined $currentDomainID && defined $fw_usage_per_domain && ref $fw_usage_per_domain eq "HASH"){
            $firewall_count = (exists $fw_usage_per_domain->{$currentDomainID}) ? scalar (keys %{$fw_usage_per_domain->{$currentDomainID}}) : 0;
            $router_count = (exists $router_usage_per_domain->{$currentDomainID}) ? scalar (keys %{$router_usage_per_domain->{$currentDomainID}}) : 0;
            ($firewall_quota, $router_quota) = getDomainOrGlobalQuota($currentDomainID);
            $domainStr = "in domain id [$currentDomainID]";
            $lic_exceeded = isExceeded($firewall_count, $firewall_quota, $router_count, $router_quota);
            $logger->print_log("Info", Logger::PROG_MESSAGE, "Used [$firewall_count] (out of [$firewall_quota]) firewalls and ".
                "[$router_count] (out of [$router_quota]) routers  $domainStr");
        }
    }
    if ($lic_exceeded && defined $fw_key && 
        ((defined $fw_usage->{$fw_key} && $fw_usage->{$fw_key} > 1) ||
         (defined $router_usage->{$fw_key} && $router_usage->{$fw_key} > 1)))
    {
        $lic_exceeded = 0;
    }
    # If verbose mode, print the whole usage hashes
    if($mode eq 'verbose')
    {
        my $detail_format = "%15s: %d\n";
        my $fw_total = 0;
        my $router_total = 0;
        foreach my $device_license_id (sort keys %{$fw_usage})
        {
            $fw_total++;
            printf "Firewall: $detail_format",$device_license_id, $fw_usage->{$device_license_id};
        }
        foreach my $router_device_license_id (sort keys %{$router_usage})
        {
            $router_total++;
            printf "Router: $detail_format",$router_device_license_id, $router_usage->{$router_device_license_id};
        }
        printf "Total unique FW Keys: %d | Total unique router Keys: %d\n", $fw_total, $router_total;
        if(defined $currentDomainID && ref $fw_usage_per_domain eq "HASH" && ref $router_usage_per_domain eq "HASH"){
            foreach my $domain (sort keys %{$fw_usage_per_domain})
            {
                foreach my $device_license_id (sort keys %{$fw_usage_per_domain->{$domain}})
                {
                    printf "Domain %s, fw id: %s: %d\n",$domain, $device_license_id, $fw_usage_per_domain->{$domain}->{$device_license_id};
                }
            }
            foreach my $domain (sort keys %{$router_usage_per_domain})
            {
                foreach my $router_device_license_id (sort keys %{$router_usage_per_domain->{$domain}})
                {
                    printf "Domain %s, router id: %s: %d\n",$domain, $router_device_license_id, $router_usage_per_domain->{$domain}->{$router_device_license_id};
                }
            }
        }
    }

    return ($firewall_count, $router_count, $lic_exceeded);
}

sub isExceeded
{
    my $firewall_count = shift;
    my $firewall_quota = shift;
    my $router_count = shift;
    my $router_quota = shift;
    my $lic_exceeded = 0;
    my $deviceLicenseType;

    $deviceLicenseType = FwaUtil::GetDeviceLicenseType();

    if ($deviceLicenseType eq FwaUtil::FIREWALL)
    {
        if ($firewall_count > $firewall_quota)
        {
            $lic_exceeded = 1;
        }
    }
    elsif ($deviceLicenseType eq FwaUtil::ROUTER)
    {
        if ($router_count > $router_quota)
        {
            $lic_exceeded = 1;
        }
    }
    else
    {
        $lic_exceeded = $firewall_count > $firewall_quota || $router_count > $router_quota;
    }

    return $lic_exceeded;
}

# Input: $fw_key - ip of firewall or tree name if we want to add 1 to it's counter.
#        $returnTotalUsagePerDomain = 1 - return a second hash with usage per domain.
# from license version 7.2 we started to count firewall usage based on the tree name instead of the ip address
#
# Output: $rc, \%fw_usage, \%fw_usage_per_domain:
#	$rc - 1 on success, 0 otherwise.
#	\%fw_usage - ref to a hash: {firewalls id} = usage of each firewall (number of reports).
#   \%fw_usage_per_domain - ref to a hash: {domain id}{firewalls id} = usage of each firewall (number of reports).
#   \%fw_usage_per_domain will be empty if $returnTotalUsagePerDomain = 0.
sub countFirewallsUsageToHash
{
    my ($fw_key, $returnTotalUsagePerDomain, $job_dir) = @_;

    if (not defined %lic_parms)
    {
        get_lic_params();    
    }

    $logger->print_log("Debug", Logger::PROG_MESSAGE, "Starting countFirewallsUsageToHash, firewall key is [$fw_key] returnTotalUsagePerDomain is [$returnTotalUsagePerDomain]");

    my $REGEXP_IP = '\d+\.\d+\.\d+\.\d+';
    my $fa_cmd = "fa_usage";
    my ($name, $myval);
    my ($device_val,$status_val, $domainID, $deviceType);
    my (%fw_usage, %fw_usage_per_domain) = ((), ());
    my (%router_usage, %router_usage_per_domain) = ((), ());

    if (defined $fw_key && $fw_key ne "")
    {
        if (!defined $job_dir || !(-d $job_dir)) {
            return 0;
        }

        # load job dir meta file
        my $current_meta_dir = FwaUtil::get_meta_dir();
        if ($current_meta_dir ne $job_dir) {
            FwaUtil::meta_dir($job_dir);
            if (!FwaUtil::read_meta_file()) {
                return 0;
            }
        }
        my $is_from_file_analysis = defined $FwaUtil::fwa_meta{'From_File_Analysis'} ? $FwaUtil::fwa_meta{'From_File_Analysis'} : undef;
        $is_from_file_analysis = (defined $is_from_file_analysis && $is_from_file_analysis eq "yes") ? "yes" : "no";
        $domainID = defined $FwaUtil::fwa_meta{'Domain_id'} ? $FwaUtil::fwa_meta{'Domain_id'} : undef;

        # from license version 7.2 we started to count firewall usage based on the tree name instead of the ip address
        # in case the flow is from file analysis, firewall usage based on the ip address
        if (($FwaLic::lic_parms{'License_version'} <= "7.1" || $is_from_file_analysis eq "yes") && $fw_key !~ /$REGEXP_IP/) {
            $logger->print_log("Info", Logger::PROG_MESSAGE, "Invalid IP address [$fw_key]");
            return 0;
        } else {
            my $deviceLicenseType = FwaUtil::GetDeviceLicenseType();

            if($FwaLic::lic_parms{'License_version'} eq "7.0")
            {
                $deviceLicenseType = FwaUtil::FIREWALL; 
            }
        	# afa 6.6 with old (<=6.5) license should treat all devices as firewalls
            if ($deviceLicenseType eq FwaUtil::FIREWALL or ($FwaLic::lic_parms{'License_version'} eq "7.0" and $deviceLicenseType ne FwaUtil::AEF))
            {
                $fw_usage{$fw_key} = 1; # start from 1 instead of from 0
                if ($returnTotalUsagePerDomain && defined $domainID && $domainID ne "") {
                    $fw_usage_per_domain{$domainID}{$fw_key}++;
                }
            }
            elsif ($deviceLicenseType eq FwaUtil::ROUTER)
            {
                $router_usage{$fw_key} = 1; # start from 1 instead of from 0
                if ($returnTotalUsagePerDomain && defined $domainID && $domainID ne "") {
                    $router_usage_per_domain{$domainID}{$fw_key}++;
                }
            }
            elsif  ($deviceLicenseType ne FwaUtil::AEF) # If device is AEF do nothing, don't change Firewall or Router license count
            {
            	$logger->print_log("Info", Logger::PROG_MESSAGE, "countFirewallsUsageToHash, device license type is [$deviceLicenseType], don't count it");
            }
        }

        # restore mete dir
        if ($current_meta_dir ne $job_dir) {
            FwaUtil::meta_dir($current_meta_dir);
            if (!FwaUtil::read_meta_file()) {
                return 0;
            }
        }

        # need to reset domainID, we will use it later
        $domainID = undef;
    }

    my $TMPFILE=`mktemp /tmp/fa_XXXXXX`;
    chomp($TMPFILE);
    my $params = sprintf("-d %s", $TMPFILE);

    if ($debug > 0)
    {
        printf "params %s\n", $params ;
    }

    my $fa_path = find_cmd($fa_cmd);
    return (0) unless $fa_path;
    # validate fa_usage command
    return (0) unless validate_cmd($fa_cmd, $fa_path);
    #run fa_usage command
    my @rc = run_cmd($fa_cmd, $params);
    if(@rc != 0)
    {
        return (0);
    }

    open META, $TMPFILE or return (0);
    while (<META>) 
    {       
        chomp;
        ($name, $myval) = split /=/ ;
    
        if($name eq "Job_status")   
        {
            $status_val=$myval; 
        }

        # from license version 7.2 we started to count firewall usage based on the tree name instead of the ip address,
        # meaning DEVICE_LICENSE_ID instead of FW_ID, also for from file analysis flow
        if($name eq "FW_ID" && $FwaLic::lic_parms{'License_version'} <= "7.1")
        { 
            $device_val = $myval;
            if ($debug) {
                printf "found %s\n", $myval;
            }
        } elsif($name eq "DEVICE_LICENSE_ID" && $FwaLic::lic_parms{'License_version'} > "7.1") {
            $device_val = $myval;
            if ($debug) {
                printf "found %s\n", $myval;
            }
        }

        if($name eq "Domain_id")
        { 
            $domainID =  $myval;
            if($debug) {
                printf "found Domain_id: %s\n", $myval;
            }
        }
        if($name eq "Device_license_type")
        {
            $deviceType = $myval;
            if($debug) {
                printf "found Device_license_type: %s\n", $myval;   
            }
        }
        # Look for '+++' in the file
        if ($_ =~ /\+{3}/)
        {     
            if(($status_val eq 'COMPLETED') and (defined $device_val)) 
            {
                # if we're still using an old (6.5 and below) license, treat everything as FW.
                if($FwaLic::lic_parms{'License_version'} eq "7.0" and defined $deviceType and $deviceType ne FwaUtil::AEF)
                {
                    $deviceType = FwaUtil::FIREWALL;
                }
                if (defined $deviceType and $deviceType eq FwaUtil::FIREWALL)
                {
                    $fw_usage{$device_val}++;
                }
                elsif (defined $deviceType and $deviceType eq FwaUtil::ROUTER)
                {
                    $router_usage{$device_val}++;
                }
                elsif (defined $deviceType and $deviceType ne FwaUtil::AEF) # If device is AEF do nothing, don't change Firewall or Router license count
                {
                    $logger->print_log("Warning", Logger::PROG_MESSAGE, "Unknown device license type $deviceType.");
                }

                if ($returnTotalUsagePerDomain) {
                    if (defined $domainID && $domainID ne "") {
                        if (defined $deviceType and $deviceType eq FwaUtil::FIREWALL)
                        {
                            $fw_usage_per_domain{$domainID}{$device_val}++;
                        }
                        elsif (defined $deviceType and $deviceType eq FwaUtil::ROUTER)
                        {
                            $router_usage_per_domain{$domainID}{$device_val}++;
                        }

                    }
                }
                if ($debug)
                {
                    my $withDomain = (defined $domainID) ? "for domain id [$domainID]" : "";
                    $logger->print_log("Debug", Logger::PROG_MESSAGE, "increasing $device_val $withDomain to " . (defined $deviceType and $deviceType eq FwaUtil::FIREWALL ? $fw_usage{$device_val} : $router_usage{$device_val}));
                }
            }
            undef $status_val;
            undef $device_val; 
            undef $domainID;
            undef $deviceType;
        }   
    }
    close META;
    unlink $TMPFILE;
    return (1, \%fw_usage, \%fw_usage_per_domain, \%router_usage, \%router_usage_per_domain);
}

# if license version > 7.1 and not from file analysis then populates DEVICE_LICENSE_ID property with Tree_Name property
# in all fwa.meta files (report, firewall)
# input: job dir, firewall dir
# assuming FwaUtil::read_meta_file() function was called before in the context of current analyze (job_dir)
sub populates_license_device_id
{
    my ($job_dir, $firewall_dir, $is_from_file_analysis) = @_;
    my $error = 1;
    my $success = 0;

    # validate arguments
    if (!defined $job_dir || !(-d $job_dir)) {
        return $error;
    }

    # read license params
    if (!FwaLic::get_lic_params())
    {
        return $error;
    }

    # load job dir meta file
    my $current_meta_dir = FwaUtil::get_meta_dir();
    if ($current_meta_dir ne $job_dir) {
        FwaUtil::meta_dir($job_dir);
        if (!FwaUtil::read_meta_file()) {
            return $error;
        }
    }

    # check if it the case of from file analysis
    if (!defined $is_from_file_analysis || (defined $is_from_file_analysis && $is_from_file_analysis ne "yes")) {
        $is_from_file_analysis = "no";
    }

    # populates DEVICE_LICESNE_ID just in cases license version > 7.1 and not from file analysis flow
    # note: license version should not be above 7.9, in case we will get there need to move to license version 8.0 etc.
    if ($FwaLic::lic_parms{'License_version'} > "7.1" && $is_from_file_analysis eq "no") {
        my $tree_name = $FwaUtil::fwa_meta{'Tree_Name'};

        # validate tree name property
        if (!defined $tree_name || $tree_name eq "") {
            return $error;
        }

        # write into job_dir (report) fwa.meta file
        FwaUtil::write_meta("DEVICE_LICENSE_ID", $tree_name);

        # write into global fwa.meta (firewall_dir) file
        if (defined $firewall_dir && -d $firewall_dir) {
            FwaUtil::meta_dir($firewall_dir);
            FwaUtil::write_meta("DEVICE_LICENSE_ID", $tree_name);
            FwaUtil::meta_dir($job_dir);
        }
    }

    # restore mete dir
    if ($current_meta_dir ne $job_dir) {
        FwaUtil::meta_dir($current_meta_dir);
        if (!FwaUtil::read_meta_file()) {
            return $error;
        }
    }

    return $success;
}

#-----------------------------------------------
# takes a command name, returns the full path
sub find_cmd    
{
    my $cmd_name = shift;
    my $find_cmd = 'which';
    my $output = run_cmd($find_cmd, $cmd_name, '2>/dev/null');
    if (! $output )
    {
	set_error("Failed to find the $cmd_name program",1);
	return undef;
    }
    # untaint returned command
    chomp($output);
    unless ($output =~ /^([^\;=|<>\+\*\? \t\n\r\f]+)$/) {
	set_error("Malformed command name returned by '$find_cmd $cmd_name'");
	return undef;
    }
    carp "$cmd_name found at $1" if $debug;
    return $1;
}

#-----------------------------------------------
# takes a full path of a signed command, checks it against its signature
# $cmd_name = hash key of command in %md5sig
# $cmd = full path to command
sub validate_cmd
{
    my ($cmd_name, $cmd) = @_;
    my $md5cmd;
    my ($md5output, $runtime_md5sig);
#
# Freebsd has md5, Linux has md5sum
#
  MD5: {
      if (-f "/usr/bin/md5sum") { $md5cmd='md5sum'; last MD5; }
      if (-f "/sbin/md5") { $md5cmd='md5 -r'; last MD5; }
      set_error("Checksum program not found.");
      return undef;
    }
#
# get the md5 signature of the command
#
    $md5output = run_cmd($md5cmd,$cmd);
    if (! defined $md5output) {
	set_error("Checksum of $cmd failed.",1);
	return undef;
    }
    ($runtime_md5sig) = $md5output =~ /^(\S+)\s+/;
    carp "Signature of $cmd_name is\t\t$runtime_md5sig" if ($debug);
    carp "Signature of $cmd_name was\t$md5sig{$cmd_name}" if ($debug); 
#
# check if it's still the same
#
    if ($runtime_md5sig ne $md5sig{$cmd_name})
    {
	set_error("The signature of $cmd_name does not match. File has been tampered with?");
	return undef;
    }
    carp("Signatures match for ($cmd_name)") if $debug;
    return 1;
}

#-----------------------------------------------
# Runs the system command specified in @_
# Returns output as an array of lines, or first line
#
sub run_cmd
{
    my $su_do = '/usr/local/bin/sudo -H';
    my $licenser = 'firmato';
    my @args = @_;
    my ($cmd_line, @output);
    my $username = getpwuid $<;
    carp("Running as $<:$username") if $debug;
#
# [AW 5 Dec 2003] only use sudo if the global flag s set
#
    if ($USE_SUDO and ($licenser ne $username))
    {
        # prepend sudo command
        unshift @args, $su_do, '-u', $licenser;
    }
    
    $cmd_line = join(' ', @args);
    carp("Running $cmd_line") if $debug;
    
    @output = `$cmd_line`;
    if ($?) {
        my $err_out = join("\n", @output);
        my $msg;
        if ($debug)
        {
            $msg = "Command $cmd_line failed with status $?\n";
        }
        $msg .= $err_out;
        set_error($msg, 0, $?);
        return undef;
    }
    carp @output if $debug;
    return wantarray ? @output : $output[0];
}

#-----------------------------------------------
# parse the output of testlic into a hash.
# one special case is the VENDOR_STRING, which gets internally
# parsed into 2 separate fields.
#
sub parse_license
{
    my @license_lines = @_;
    my $line;
    my ($key, $val);

    foreach $line (@license_lines)
    {
        ($key, $val) = $line =~ /^(\S+)=(.*)$/;
        if (defined $val)
        {
            if ($debug > 0 )
            {
            	print "$key = $val\n";
            }
    
            # a FlexLM date with year=0 indicates a permanent license
            next if ($key eq 'Expires_on' and $val =~ /^.*-.*-0$/);
            
            # 01-jan-1970 indicates a permanent license with our license
            next if ($key eq 'Expires_on' and $val eq "permanent");

            $lic_parms{$key} = $val;
        }
    }
}

#-----------------------------------------------
# Error handler routine. Sets or appends to $error_msg,
# sets $error_status if provided.
sub set_error
{
    my ($msg, $append, $status) = @_;
    if (defined $status)
    {
        $error_status = $status;
    }
    chomp $msg;
    carp $msg if $debug;
    if ($append)
    {
        chomp $error_msg;
        $error_msg .= "\n$msg";
    }
    else
    {
        $error_msg = $msg;
    }
}


sub check_online_license
{
    my @args = @_;
    my @fw_args;
    my $mode = shift;
    my $lic_type = shift;
    my $fw_key = shift;
    my $job_dir = shift;
 
    $fw_args[0] = $mode;
    $fw_args[1] = $fw_key;
    $fw_args[2] = $job_dir;

    #   Get the account name
    if(!defined($FwaLic::lic_parms{'Account_name'}))
    {
        carp "reading license\n" if($debug > 0);
        if (! FwaLic::get_lic_params())
        {
            return undef;
        }
    }
    
    my ($firewall_count, $router_count, $report_count, $lic_exceeded);

    if($lic_type eq 'Online')
    {
        $report_count = count_reports($mode);
        chomp($report_count);
    	$report_count =~ s/^\s+//;
        # Online per report, can't be with domains, hence take 'Report_quota', and not quota of domain.
        my $quota = $FwaLic::lic_parms{'Reports_quota'};
        $lic_exceeded = $report_count >= $quota;
        $logger->print_log("Info", Logger::PROG_MESSAGE, "check_online_license: Used $report_count reports (out of $quota)");
    }
    elsif ($lic_type eq 'PerFW-Online')
    {
        # checkLicFwUsageAndExceeded also prints a log message regarding the license usage, no need to print twice here.
        ($firewall_count, $router_count, $lic_exceeded) = checkLicFwUsageAndExceeded(@fw_args);
        return undef if(!defined $firewall_count || !defined $lic_exceeded || ($FwaLic::lic_parms{'License_version'} >= "7.1" && !defined $router_count));
    }
    else
    {
	    $logger->print_log("Error", Logger::PROG_MESSAGE, "Illegal license type ($lic_type)");
        return undef;
    }

    return ReturnOnlineLicenseCheckResults($firewall_count, $router_count, $report_count, $lic_exceeded, $lic_type);
}
# Used to return the appropriate values from check_online_license based on lic_type
# input:
#   firewall_count  - number of firewalls
#   router_count    - number of routers
#   report_count    - number of reports
#   lic_exceeded    - whether or not quota was exceeded
#   lic_type        - license type
# output: the relevant input arguments based on lic_type
sub ReturnOnlineLicenseCheckResults
{
    my ($firewall_count, $router_count, $report_count, $lic_exceeded, $lic_type) = @_;
    if ($lic_type eq "Online")
    {
        return ($report_count, $lic_exceeded);
    }
    else
    {
        return ($firewall_count, $router_count, $lic_exceeded);
    }
}

#-----------------------------------------------------
# function to connect to AlgoSec web server using wget and get back an activated license
# sending the MAC address, License ID & account name
# -----------------------------------------------------
sub get_activation_license
{
    my ($License_Id,$Account_Name,$licensePath) = @_;
    my $error_message = undef;
    my %error_codes = ('LICENSE_INVALID_REQUEST'     =>'01',
    		           'LICENSE_INCLUDE_ERROR'       =>'02',
		               'LICENSE_MYSQL_ERROR'         =>'03',
		               'LICENSE_DUPLICATE_ACTIVATION'=>'04',
		               'LICENSE_ILLEGAL_ACTIVATION'  =>'05',
		               'LICENSE_CREATE_ERROR'        =>'06');

    
    if (! defined $License_Id || ! defined $Account_Name || ! defined $licensePath)
    {
    	die "Error: could not start activation process!\n";
    }
    
    my $cmd = "wget";
    #   wait for 20 seconds, wait 5 seconds between the three retries, work in quiet mode 
    # [AW] increase timeout to 3 minutes, only 1 try
    # [AK] use --user, --password command line arguments instead
    #      of fa:lic@www.algosec.com (to avoid problems with 
    #      some proxy servers) - done in get_wget_switch
    my $params =  "--output-document=- --waitretry=5 --timeout=180 --tries=1 -q";
    my $curl_params = "--connect-timeout 180 -k --user fa:lic -s";
    my $use_curl = 0;
    # [AW] switch to https
    # conditionally add the "no-check-certificate" for https
    #my $url = "https://fa:lic\@www.algosec.com/license/activate.php";
    my $url = "https://www.algosec.com/license/activate.php";
    my $url2 = "http://www.algosec.com/license/activate.php";
    # for temp - build out url
    # my $url = "http://algo:sec\@www.algosec.com/temp/algosec-04-12-26/license/activate.php";
    my ($activate_response,@licenseLines);
    
    my $cmd_path = `which wget`;
    if($? != 0) {
	#die ("Error: Cannot find wget\n");
	$logger->print_log("Info", Logger::PROG_MESSAGE, "Cannot find wget - using curl");

	$use_curl = 1;
    }
    
    chomp($cmd_path);

    # find the mac address for the computer eth0
    my $getMacAddressCommand = "/sbin/ifconfig eth0 | grep eth0 | awk '".'{print $NF}'."'";
    my $MAC_Address = `$getMacAddressCommand`;
    #clean the mac address  - to have only a-fA-F0-9
    $MAC_Address =~ tr[0-9a-fA-F][]dc;
    $MAC_Address =~ s/\s//g;
    if(! defined $MAC_Address or $MAC_Address eq "") {
        $logger->print_log("Error", Logger::PROG_MESSAGE, "Failed to obtain MAC address - activation stopped.\n" .
		"AFA uses the MAC address of eth0 for licensing.\n" .
		"Please verify that the server has this interface, and its MAC address is valid:\n" .
		"/sbin/ifconfig eth0");

        die "Error: Failed to obtain MAC address - activation stopped.\n" .
	   "AFA uses the MAC address of eth0 for licensing.\n" .
           "Please verify that the server has this interface, and its MAC address is valid:\n" .
           "/sbin/ifconfig eth0\n";
    }
	$logger->print_log("Info", Logger::PROG_MESSAGE, "MAC address for license activation: $MAC_Address");    
    
    # prepare the get fields to be send with the url with license id, account name, and mac address    
    my $param_str ="?License_Id=$License_Id\\&Account_Name=$Account_Name\\&MAC_Address=$MAC_Address";
    
	$logger->print_log("Info", Logger::PROG_MESSAGE, "Obtaining license for: License_Id=$License_Id, Account_Name=$Account_Name");
    # prepare the full command string

    $params .= " " . get_wget_switch();

    my $exec_cmd = sprintf("%s %s %s%s", $cmd_path, $params, $url, $param_str);
    
	$logger->print_log("Info", Logger::PROG_MESSAGE, "Accessing the AlgoSec license server");
    
    if (defined $ENV{'https_proxy'} and $ENV{'https_proxy'} ne "")
    {
    	# Add relevant curl switches
    	my ($https_proxy) = ($ENV{'https_proxy'} =~ /:\/\/(.+)/);
    	if ($https_proxy =~ /@/) {
    		my ($proxy_user,$proxy) = ($https_proxy =~ /(.*)@(.*?)\s*$/);
    		$curl_params .= " --proxy $proxy --proxy-user '$proxy_user'";
    	} else {
    		$curl_params .= " --proxy $https_proxy";
    	}
    	
		$logger->print_log("Info", Logger::PROG_MESSAGE, "using proxy " . $ENV{'https_proxy'});
    }

    #   run the wget command and check that the machine is connected to the Internet
    #   The output is returned
	my $wget_response = "";
    if (! $use_curl) {
	    $wget_response=`$exec_cmd 2>&1`;
    }
	
	# split wget response into lines
	($activate_response,@licenseLines) = split("\n",$wget_response);
	# all the license lines are joined back
	my $licenseContent = join("\n",@licenseLines);
    
    # if activate response doesn't have the word LICENSE then error on connection to webserver
    if ($activate_response !~ /LICENSE/) 
    {
    	# wget failed, try plan B (wget with http)
		$logger->print_log("Info", Logger::PROG_MESSAGE, "wget using https failed. Trying http");
    	
    	$exec_cmd = sprintf("%s %s %s%s", $cmd_path, $params, $url2, $param_str);
    	if (! $use_curl) {
    		$wget_response=`$exec_cmd 2>&1`;
    	}
 
	     # split wget response into lines
	    ($activate_response,@licenseLines) = split("\n",$wget_response);
	    # all the license lines are joined back
	    $licenseContent = join("\n",@licenseLines);
	    
	    if ($activate_response !~ /LICENSE/) 
    	{
    		# wget failed with both options, try plan C (curl)
			$logger->print_log("Info", Logger::PROG_MESSAGE, "wget using http failed. Trying curl with https");
    		
    		$cmd_path = `which curl`;
    		if($? != 0) {
				$logger->print_log("Error", Logger::PROG_MESSAGE, "Cannot find curl (and wget failed)");
    			die "Error: Cannot find curl (and wget failed)\n";
		    }
		    chomp($cmd_path);
		    
		    $exec_cmd = sprintf("%s %s %s%s", $cmd_path, $curl_params, $url, $param_str);
		    $wget_response=`$exec_cmd 2>&1`;
 
		     # split wget response into lines
		    ($activate_response,@licenseLines) = split("\n",$wget_response);
		    # all the license lines are joined back
		    $licenseContent = join("\n",@licenseLines);
    	}
    }
    if(!($activate_response =~ /LICENSE/)) 
    {
    	my $message=
  "\nActivation: The Firewall Analyzer failed to reach the license server.  \n" .
  "If you use a proxy server to access the Internet, \n" .
  "please use the Tools->Options menu to configure your proxy settings.";

		dump_err("", "$wget_response");

		$logger->print_log("Error", Logger::PROG_MESSAGE, $message);
		die $message;
    }
    # check if response is license ok then activation is ok
    if ($activate_response =~ /LICENSE_CREATED_OK/)
    {
    	# the second part of first line is the new activation file name
    	my ($licenseFileName) = ($activate_response =~ /([^\s]+)$/);
    	
		$logger->print_log("Info", Logger::PROG_MESSAGE, "Activation succeeded, LicenseFileName = $licenseFileName");
    	
        #open a new file for activated license and write the license 
        open LICENSE, ">$licensePath/$licenseFileName" or die "Error: writing to license file!\n";
        print LICENSE  $licenseContent;
        close LICENSE;
        # print the success message back to the java and exit 
        return $activate_response;
    }
    # else if resoponse is duplicate activation then print notice
    if ($activate_response =~ /LICENSE_DUPLICATE_ACTIVATION/)
    {
    	#call sub to prepare the activation error message
	$error_message = activation_error_message($license_trouble_file,"License ID $License_Id has already been activated.");
	# if could not prepare the error message from file then just print simple notice
	if (! defined $error_message)
	{
		$logger->print_log("Error", Logger::PROG_MESSAGE, "License activation failed");
        die "Error: activation failed!\n";
	}
	else
	{
		$logger->print_log("Error", Logger::PROG_MESSAGE, $error_message);
	    die $error_message;
	}
    }
    # else response is not ok then also error in activation
    else
    {
    	my ($error_code) = ($activate_response =~ /(LICENSE[^\s:]*)/);
    	#call sub to prepare the activation error message
		$error_message = activation_error_message($license_trouble_file,"(error code ".$error_codes{$error_code}.")");
		# if could not prepare the error message from file then just print simple notice
		if (! defined $error_message)
		{
			$logger->print_log("Error", Logger::PROG_MESSAGE, "License activation failed");
            die "Error: activation failed!\n";
		}
    	else
		{
			$logger->print_log("Error", Logger::PROG_MESSAGE, $error_message);
            die $error_message;
		}
    }
}
# error message from the license - trouble .txt file (used for get_activation_license sub)
sub activation_error_message
{
    my ($src_file,$license_error_text) = @_;
    my $errorMessage="";

    open ERROR_FILE, "<$src_file" or return undef;
    
    while (<ERROR_FILE>)
    {
	s/\%LICENSE_ERROR/$license_error_text/g;
	
	$errorMessage.= $_;
    }

    close ERROR_FILE;
    return $errorMessage;
}

#------------------------------------------------------------------------------
# dump an error file into the global history file
# can't just print to STDERR because Java catches that 
# and prints it to screen
#------------------------------------------------------------------------------
sub dump_err
{
    my $LOG_FILE = "$ENV{HOME}/.fa-history";
    my ($filename, $msg) = @_;

    `echo "Error connecting to license server. Response was:" >> $LOG_FILE`;

    if (defined $filename and $filename ne "")
    {
	`cat $filename >> $LOG_FILE`;
    }
    
    if (defined $msg and $msg ne "")
    {
	open ERR, ">>$LOG_FILE";
	print ERR $msg;
	close ERR;
    }

}

#-----------------------------------------------
# wget 1.9 and earlier are not fussy about https certificates
# and don't support the "--no-check-certificate" switch.
# wget 1.10 and later is fussy so we MUST use the switch
#
# There is also a difference in the --user and --password
# switches (1.9 uses --http-user and --http-passwd)
# 
sub get_wget_switch
{
#    my $wget1_10_switch = "--no-check-certificate";
    my $wget1_10_switch = "--no-check-certificate --user=fa --password=lic";
    my $wget1_9_switch = "--http-user=fa --http-passwd=lic";

    my $wget_vers = `wget --version | grep Wget`;

    my ($major_ver, $minor_ver) = $wget_vers =~ /\s(\d+)\.(\d+)/;

    if ( ($major_ver > 1) or
	 (($major_ver eq 1) and ($minor_ver > 9)) )
    {
	return $wget1_10_switch;
    }
    else
    {
#	return "";
	return $wget1_9_switch;
    }
}


# Input: $currentDomainID - domain id. If undef, we would try to find the current domain id.
# Output: $firewallsQuota, $routersQuota: if we are in a domain, return the domain's firewalls and routers quota. If we are not in a domain, 
#   or the domain quota is not defined (or not a number), return the global license firewall and router quotas 
#   ($FwaLic::lic_parms{'Routers_quota'} and $FwaLic::lic_parms{'Firewalls_quota'}).
sub getDomainOrGlobalQuota
{
    my ($currentDomainID) = @_;

    $logger->print_log("Debug", Logger::PROG_MESSAGE, "Look for global/domain quota");

    my $firewallsQuota = $FwaLic::lic_parms{'Firewalls_quota'};
    my $routersQuota = $FwaLic::lic_parms{'Routers_quota'};
    # If we didn't get currentDomainID, try to find it.
    if(!defined $currentDomainID){
        $currentDomainID = get_current_domain_id();
    }
    if(defined $currentDomainID){
        my $domainFirewallsQuota = domains_mng::get_domain_firewalls_quota($currentDomainID);
        my $domainRoutersQuota = domains_mng::get_domain_routers_quota($currentDomainID);
        $domainFirewallsQuota =~ s/\s//g;
        $domainRoutersQuota =~ s/\s//g;
        if(!defined $domainFirewallsQuota || $domainFirewallsQuota !~ /^\d+$/){
            $logger->print_log("Info", Logger::PROG_MESSAGE, "Domain id [$currentDomainID] does not have firewalls quota, take global firewalls quota instead [$firewallsQuota]");
        }else{
            $firewallsQuota = $domainFirewallsQuota;
            $logger->print_log("Debug", Logger::PROG_MESSAGE, "Return Domain id [$currentDomainID]'s firewalls quota");
        }
        if(!defined $domainRoutersQuota || $domainRoutersQuota !~ /^\d+$/){
            $logger->print_log("Info", Logger::PROG_MESSAGE, "Domain id [$currentDomainID] does not have routers quota, take global routers quota instead [$routersQuota]");
        }else{
            $routersQuota = $domainRoutersQuota;
            $logger->print_log("Debug", Logger::PROG_MESSAGE, "Return Domain id [$currentDomainID]'s routers quota");
        }
    }
    return ($firewallsQuota, $routersQuota);
}

# Input: $globalLicenseFeatures - reference to a hash that contain all license features (lic_params)
#   e.g.:
#   Expires_on		=> 07-dec-2029
#   report_quota    => 200
#   Issued_on		=> 07-Apr-2013
#   modules			=> Core;Optimization;Risk;FireFlow;ActiveChange;Domains
# Output: -1 if expiration date, 0 otherwise
# This function updates the input hash with the current domains': modules and Expires_on.
# We do not update the quota, since we need to save the global quota as well, for lic exceeded tests
sub updateDomainFeatures
{
    my ($globalLicenseFeatures) = @_;
    
    $logger->print_log("Debug", Logger::PROG_MESSAGE, "Look for domain features");
    # If $globalLicenseFeatures hash doesn't exist, return, nothing to update 
    return 0 if(!defined $globalLicenseFeatures || ref $globalLicenseFeatures ne "HASH");
    my $currentDomainID = get_current_domain_id();

    if(!defined $currentDomainID || $currentDomainID !~ /^\d+$/){
        $logger->print_log("Debug", Logger::PROG_MESSAGE, "Not signed into domain, not going to update features");
        return 0;
    }
    my $domainData = domains_mng::returnDomainDataByID($currentDomainID);
    
    if(!defined $domainData){
        $logger->print_log("warning", Logger::PROG_MESSAGE, "Could not find data for domain id [$currentDomainID]");
        return 0;
    }
    my $msg;
    # Update domain's modules
    if(exists $domainData->{'modules'}){
        my @domainModules = split(/;/, $domainData->{'modules'});
        my @globalModules = split(/;/, $globalLicenseFeatures->{'Modules_'});

        if(@domainModules && scalar @domainModules > 0){
            # FireFlow module: 'FireFlow' BusinessFlow module comes with number of applications: 'BusinessFlow-50'
            my @globalFForBFModules = grep(/FireFlow|BusinessFlow\-\d+/i, @globalModules);
            # Add FF and BF modules to @domainModules if exists in the global license.
            # This is to make sure that the global license will determine if they exist or not, even if the xml is wrong (AFA-17208)
            @domainModules = (@domainModules, @globalFForBFModules) if(scalar(@globalFForBFModules) > 0);
            # Find the domain and global modules intersection
            my $intersection = FwaUtil::ArraysIntersection(\@domainModules, \@globalModules);
            if(scalar @$intersection > 0){
                $msg = "Updating license Modules_ to the global and domain's id [$currentDomainID] modules intersection [@$intersection]";
                $globalLicenseFeatures->{'Modules_'} = join(";", @$intersection);
            }else{
                $msg = "There is no intersection between global license Modules and domain's id [$currentDomainID] modules - keep the global modules";
            }
            $logger->print_log("Debug", Logger::PROG_MESSAGE, $msg);
        }
    }
    # Update domain's license expiration
    if(exists $domainData->{'license_expires_on_timestamp'}){
        my $domainExpirionTimeStamp = $domainData->{'license_expires_on_timestamp'};
        if(defined $domainExpirionTimeStamp && $domainExpirionTimeStamp ne "" && $domainExpirionTimeStamp =~ /^\s*\d+\s*$/){
            my $globalExpiresTimeStamp = $globalLicenseFeatures->{'Expires_on'};
            # globalExpiresTimeStamp is of format 07-may-2013
            $globalExpiresTimeStamp =~ s/-//g;
            # ckp_date2local gets this format: 07may2013
            $globalExpiresTimeStamp = FwaUtil::ckp_date2local($globalExpiresTimeStamp);
            # If the minimal expiration date is of the domain - update the expiration date.
            if($globalExpiresTimeStamp > $domainExpirionTimeStamp){
                # license_local2date returns this date format 07-may-2013, or undef when fails
                if(my $domainExpirationLicFormat = FwaUtil::license_local2date($domainExpirionTimeStamp)){
                    $globalLicenseFeatures->{'Expires_on'} = $domainExpirationLicFormat;
                    $msg = "Updating license Expires_on to domain's id [$currentDomainID] Expires_on [$domainExpirationLicFormat]";
                    $logger->print_log("Debug", Logger::PROG_MESSAGE, $msg);
                    my $currDateTimeStamp = FwaUtil::currDate2local();
                    if($domainExpirionTimeStamp < $currDateTimeStamp){
                        $logger->print_log("Error", Logger::PROG_MESSAGE, "License check failed: expired");
                        return -1;
                    }
                }
            }
        }
    }
    return 0;
}

# prints lic info to log
sub PrintLicDebugInfo
{
     if ($ENV{DEBUG} > 20)
    {
        printf "Read %s (%s) license, License_id=%s\n",
        $FwaLic::lic_parms{'License_type'},
        FwaLic::GetQuotaString(),
        $FwaLic::lic_parms{'License_id'};
    }
}

# output: string "reports_quota" or "firewalls_quota;routers_quota"
sub GetQuotaString
{
    if ($FwaLic::lic_parms{'License_type'} eq 'PerReport' || $FwaLic::lic_parms{'License_type'} eq 'Online')
    {
        return "$FwaLic::lic_parms{'Reports_quota'}";
    }
    elsif ($FwaLic::lic_parms{'License_type'} eq 'PerFW' || $FwaLic::lic_parms{'License_type'} eq 'PerFW-Online')
    {
        return "$FwaLic::lic_parms{'Firewalls_quota'};$FwaLic::lic_parms{'Routers_quota'}";
    }

}

1; # avoid Perl whining

