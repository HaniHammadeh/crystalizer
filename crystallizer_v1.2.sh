#!/bin/bash

# ------------------------------------------------------------------
# [Author] 
# Hani Hammadeh
# hani.hammadeh@gmail.com
# [Descriptio]
# This Script is used for hardening CentOS 6.4 Server
# VERSION=1.0
# ------------------------------------------------------------------

### in this part we will backup the files that will undergo some changes.
backupfile=backup_` date +%Y_%m_%d_%H%M%S`.tar.gz
rm -rf /root/backup
mkdir /root/backup
cp -rpf /usr/local/ria/analyzer/www/conf/httpd.conf /root/backup
cp -rpf /etc/ssh/sshd_config /root/backup
cp -rpf /etc/bashrc /root/backup
cp -rpf /bin/su /root/backup
cp -rpf /etc/sysctl.conf /root/backup
cp -rpf /etc/profile /root/backup
cp -rpf /etc/login.defs /root/backup
cp -rpf /etc/sudoers /root/backup
cp -rpf /etc/pam.d/system-auth /root/backup
cp -rpf /boot/grub/grub.conf /root/backup
 tar -czvf $backupfile /root/backup
##Baseline – Apache - Default------------------------------------------
httpdfile=/usr/local/ria/analyzer/www/conf/httpd.conf
echo $httpdfile
##1  Keep Apache Version Updated
##2 Run the Server with a Non-Privileged User
echo " Run the Server with a Non-Privileged User"
echo "The server by default is running with a Non-Privileged User (agama)."

####Avoid Directory Listing
echo " Avoid Directory Listing"
###    Options +Indexes
sed -i 's/Options +Indexes/Options -Indexes/g' $httpdfile
####Avoid Symbolic Links Use
echo "####Avoid Symbolic Links Use"
 #"FollowSymLinks#
sed -i 's/FollowSymLinks//g' $httpdfile
####Forbid Access to .htaccess
echo "####Forbid Access to .htaccess"
echo "denied by default"

####Disable Personal Pages Feature
echo "####Disable Personal Pages Feature"

####Avoid Unnecessary Information Disclosure
###ServerTokens Prod
echo "ServerTokens Prod" >> $httpdfile
####Remove Service Information from Error Pages
##ServerSignature Off
echo "ServerSignature Off" >> $httpdfile
####Include restrictions to .old and .bak files
####Remove Unnecessary Support to SSIs
echo " Unnecessary Support to SSIs is not included by default"
####Avoid Using File Extensions to Allow Execution
### to be asked to agama
echo "AddHandler cgi-script .old .bak " >> $httpdfile
echo "Options -ExecCGI" >> $httpdfile
####---------------------------------------------------------------------
###1.3 Baseline – Sendmail – Default
chmod 0000 /usr/sbin/sendmail

###1.4 Baseline – OpenSSH/SunSSH – Default
sshdfile=/etc/ssh/sshd_config
###Keep the Version Updated
###Forbid Logins with Empty Passwords
echo "Forbid Logins with Empty Passwords, Forbidden by default"
###Forbid SuperUser Direct Access
##-PermitRootLogin yes
sed -i '/^#PermitRootLogin/c\PermitRootLogin no' $sshdfile
###Disable Rhosts Use
echo "Disable Rhosts Use, disabled by default"
###Use Protocol 2 Only
echo "###Use Protocol 2 Only, by default is 2"
###Reduce the number of allowed login tries
#-MaxAuthTries 3
echo "MaxAuthTries 3" >> $sshdfile
###Define specific Log Facility to the Service
echo "###Define specific Log Facility to the Service, by default"
###Inactive Sessions
echo "###Inactive Sessions, by default is correct"
###Reduce the number of maximum non authenticated connections allowed
#-MaxStartups 5
echo "MaxStartups 5" >> $sshdfile
###Reduce the allowed time to enter the password
#-LoginGraceTime 45
echo " LoginGraceTime 45" >> $sshdfile
###Use privilege separation
echo "###Use privilege separation, enabled by default"

####-----------------------------------------------------------------------
###1.5 Baseline – Linux – Default (RedHat/CentOS/Fedora)
###Include password on Boot Loader
#-password --encrypted --md5 0nizK3Un$J7g1Gt6OAl53rtL/SzQKs1
#-grub-crypt
sed -i "13ipassword --md5 \$1\$Z.a3h1\$JRbqafRafzPAYtxs1gMth0" /boot/grub/grub.conf
###Enable Protection Against SYN Floods
echo "###Enable Protection Against SYN Floods,enabled by default"
###Disable Trust Relationships
echo "###Disable Trust Relationships, old fashion ssh"
###Restrict Access to the Boot Loader Configuration
echo " ###Restrict Access to the Boot Loader Configuration, by default restricted"
###Disable Unnecessary Services
for i in `chkconfig --list|awk {'print $1'}`
	do
		chkconfig $i off
	done
for i in rsyslog sshd iptables network readahead_early microcode_ctl messagebus lvm2-monitor irqbalance crond auditd analyzer
	do
		chkconfig $i on
	done
echo "done services"
###Restriction NFS exports
echo "nfs service is disabled by default"
###Disable Built-in Users’ Shells
echo "###Disable Built-in Users’ Shells, by default disabled"

###Restrict Access to Auditing Files
for a in /var/log/*
do
	if [ -f $a ]; then
		chmod 600 $a
	else
		chmod 700 $a
	fi
done
###Configure logrotate to create auditing files with restrictive permissions
### this is by default is correct
###Remove write permission of "others" in /etc files.
### a small script to do it
chmod o-w /etc/*
###Define Restrictive Default umask, need to look again in here
echo "if [ "'`'id -u'`'" != 0 ]; then umask 022; else umask 077; fi" >> /etc/bashrc
###Configure Maximum Time Between Password Changes
#PASS_MAX_DAYS 30
sed -i '/PASS_MAX_DAYS/c\PASS_MAX_DAYS    30/' /etc/login.defs
###Define Minimum Password Length
sed -i '/PASS_MIN_LEN/c\PASS_MIN_LEN    8/' /etc/login.defs
###Block passwords from system's built-in users
#usermod -L USER
for i in `awk -F: '{if($3 <=497 && $3!=0) print $1}' /etc/passwd`
do
	usermod -L $i
done
###Restrict Access to su Command
password="mypassword";pass=$(perl -e 'print crypt($ARGV[0], "password")' $password); useradd -p $pass username
usermod -G wheel alfalak
chown root.wheel /bin/su  
chmod 4750 /bin/su
###Restrict CC/GCC Use
#### not includede in the system
###Avoid Insecure PATH Variable to Superusers
### by default is correct
###Ignore Broadcasts
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
###Correct Temporary Directories Permissions
chmod 1777 /tmp /var/tmp
###Enable Password Complexity Checking
sed -i '/password    requisite/c\password    requisite     pam_cracklib.so try_first_pass retry=3 type= difok=4 minlen=8 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=0' /etc/pam.d/system-auth
###Disable ctrl+alt+del function
sed -i 's/\exec \/sbin\/shutdown -r now "Control-Alt-Delete pressed"/ #exec \/sbin\/shutdown -r now "Control-Alt-Delete pressed"/g'  /etc/init/control-alt-delete.conf
###Block Spoofed Packets
echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf
###Disable Routing Between Interfaces
echo "net.ipv4.conf.all.forwarding = 0" >> /etc/sysctl.conf
###Block Source-Routed Packets
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
###Remove Unnecessary Aliases
###by default 
###Restrict crontab Use
echo "root" > /etc/cron.allow
###Restrict AT Use
echo "root" > /etc/at.allow
###Enable Timeout for Idle Sessions
echo "TMOUT=300 " >> /etc/profile
echo "readonly TMOUT" >> /etc/profile
echo "export TMOUT" >> /etc/profile
###Forbid packets with redirection
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
###Specify number of previous passwords which cannot be reused
sed -i '/password    sufficient/c\password    sufficient    pam_unix.so remember=4 sha512 shadow nullok try_first_pass use_authtok' /etc/pam.d/system-auth
###Configure minimum time between password changes
echo "PASS_MIN_DAYS 7" >> /etc/login.defs
###Define the facility and level off the log to sudo
echo "Defaults syslog=authpriv,syslog_goodpri=info,syslog_badpri=info" >> /etc/sudoers

###Decrease the Number of Incorrect Login Attempts
echo "auth required pam_tally.so deny=3 unlock_time=60 magic_root" >> /etc/pam.d/system-auth
###Log Suspicious Packets
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
