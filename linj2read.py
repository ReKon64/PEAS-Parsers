#!/usr/bin/env python3
import json
import re

with open("/home/rekon/json2read/beauty.json", "r") as f:
  c = json.loads(f.read())

def sep():
  print('-' * 40)

#--- Basic information

root = c['Basic information']['lines']

sep()
print(root[2]['clean_text'])
print(root[3]['clean_text'])
sep()


#--- System Information
# This is a better way to traverse the "tree" probably
root = c['System Information']['sections']['Operative system']['lines']

exclusions = ['Distributor ID', 'Release']
clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and all(exclusion not in item['clean_text'] for exclusion in exclusions)]

for item in range(len(clean)):
  print(clean[item])

print(f"PATH: {c['System Information']['sections']['PATH']['lines'][0]['clean_text']}")
sep()

#  Users with Console
print("Users with set shells")
root = c['Users Information']['sections']['Users with console']['lines']
clean = [item['clean_text'] for item in root]
for item in range(len(clean)):
  print(clean[item])
sep()

# Is there mail app? / Searching installed mail applications
print("Mail + RelevantApp")
root = c['Other Interesting Files']['sections']['Searching installed mail applications']['lines']
exclusions = []
clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and all(exclusion not in item['clean_text'] for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])


root = c['Other Interesting Files']['sections']['Mails (limit 50)']['lines']
exclusions = []
clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and all(exclusion not in item['clean_text'] for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Files with Interesting Permissions
# SUID
print("Non-default SUID Files")
root = c['Files with Interesting Permissions']['sections']['SUID - Check easy privesc, exploits and write perms']['lines']
exclusions = [
  r'/usr/bin(\[1;31m)?/newgrp',
  r'/usr/bin/newgrp',
  r'/usr/bin/gpasswd',
  r'/usr/bin/su',
  r'/usr/bin(\[1;31m)?/umount',
  r'/usr/bin/umount',
  r'/usr/bin/chsh',
  r'/usr/bin/fusermount3',
  r'/usr/bin/sudo',
  r'/usr/bin(\[1;31m)?/sudo',
  r'/usr/bin(\[1;31m)?/passwd',
  r'/usr/bin/passwd',
  r'/usr/bin(\[1;31m)?/mount',
  r'/usr/bin/mount',
  r'/usr/bin(\[1;31m)?/chfn',
  r'/usr/bin/chfn',
  r'/usr/libexec/polkit-agent-helper-1',
  r'/usr/lib/openssh/ssh-keysign',
]

#// Exclude all files only writeable by root user.
exclusions = [r'-rwsr-xr-x\s+\d+\s+root\s+root\s+\d+[KMG]?\s+.*\s+' + pattern for pattern in exclusions]
exclusions = [pattern + r'.*' for pattern in exclusions]

exclusions.extend([
  r'-rwsr-xr--\s+\d+\s+root\s+messagebus.*.dbus-daemon-launch-helper',
])

clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# SGID
print("Non-default SGID Files")
root = c['Files with Interesting Permissions']['sections']['SGID']['lines']

exclusions = [
  r'/usr/sbin/pam_extrausers_chkpwd',
  r'/usr/bin/expiry',
  r'/usr/bin/ssh-agent',
  r'/usr/bin/wall',
  r'/usr/sbin/unix_chkpwd',
  r'/usr/bin/write.ul',
  r'/usr/bin/crontab',
  r'/usr/bin/chage',
  r'/usr/lib/x86_64-linux-gnu/utempter/utempter'
]

exclusions = [r'-rwxr-sr-x\s+\d+\s+root\s+(?:root|shadow|crontab|tty|_ssh|utmp)\s+\d+[KMG]?\s+.*\s+' + pattern for pattern in exclusions]
exclusions = [pattern + r'.*' for pattern in exclusions]

clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Backup files (limited 100)
print("Uncommon Backup matches")
root = c['Other Interesting Files']['sections']['Backup files (limited 100)']['lines']

exclusions = [
  r'/etc/apt/sources.list.curtin.old',
  r'/var/lib/systemd/deb-systemd-helper-enabled/dpkg-db-backup.timer.dsh-also',
  r'/var/lib/systemd/deb-systemd-helper-enabled/timers.target.wants/dpkg-db-backup.timer',
  r'/usr/src/linux-headers-5.15.0-88/tools/testing/selftests/net/tcp_fastopen_backup_key.sh',
  r'/usr/lib/python3/dist-packages/sos/report/plugins/ovirt_engine_backup.py',
  r'/usr/lib/python3/dist-packages/sos/report/plugins/__pycache__/ovirt_engine_backup.cpython-310.pyc',
  r'/usr/lib/modules/5.15.0-88-generic/kernel/drivers/net/team/team_mode_activebackup.ko',
  r'/usr/lib/modules/5.15.0-88-generic/kernel/drivers/power/supply/wm831x_backup.ko',
  r'/usr/lib/systemd/system/dpkg-db-backup.timer',
  r'/usr/lib/systemd/system/dpkg-db-backup.service',
  r'/usr/lib/x86_64-linux-gnu/open-vm-tools/plugins/vmsvc/libvmbackup.so',
  r'/usr/share/man/man8/vgcfgbackup.8.gz',
  r'/usr/share/doc/manpages/Changes.old.gz',
  r'/usr/share/doc/telnet/README.old.gz',
  r'/usr/share/info/dir.old',
  r'/usr/share/byobu/desktop/byobu.desktop.old',
  r'/usr/libexec/dpkg/dpkg-db-backup',
]

exclusions = [r'(?:-rwxr-xr-x|-rw-r--r--)\s+\d+\s+root\s+root\s+\d+[KMG]?\s+.*\s+' + pattern for pattern in exclusions]
exclusions = [pattern + r'$' for pattern in exclusions]

clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Searching tables inside readable .db/.sql/.sqlite files (limit 100)
root = c['Other Interesting Files']['sections']['Searching tables inside readable .db/.sql/.sqlite files (limit 100)']['lines']
print("Uncommon .db .sql .sqlite files")

exclusions = [
  r'Found /var/lib/PackageKit/transactions.db.*',
  r'Found /var/lib/command-not-found/commands.db.*',
  r'-> Extracting tables from /var/lib/PackageKit/transactions.db.*',
  r'-> Extracting tables from /var/lib/command-not-found/commands.db.*',
]
clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Easy File Misconfigs / AppArmor binary profiles
print("Easy File Misconfigs")
root = c['Files with Interesting Permissions']['sections']['AppArmor binary profiles']['lines']
exclusions = [
  r'sbin.dhclient',
  r'usr.bin.man',
  r'usr.bin.tcpdump',
  r'usr.sbin.rsyslogd',
]
exclusions = [r'-rw-r--r--\s+\d+\s+root\s+root\s+\d+[KMG]?\s+.*\s+' + pattern for pattern in exclusions]
exclusions = [pattern + r'.*' for pattern in exclusions]
exclusions.extend([
  r'Hashes inside passwd file\? \.+ No',
  r'Writable passwd file\? \.+ No',
  r'Can I read shadow files\? \.+ No',
  r'Can I read shadow plists\? \.+ No',
  r'Can I write shadow plists\? \.+ No',
  r'Can I write in network-scripts\? \.+ No',
  r'Credentials in fstab/mtab\? \.+ No',
  r'Can I read opasswd file\? \.+ No',
  r'Can I read root folder\? \.+ No',
])

clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Files with Capabilities

# print("Files with Capabilities")
# root = c['Files with Interesting Permissions']['sections']['Capabilities']['lines']

# Users with Capabilities
print("Users with Capabilities")
root = c['Files with Interesting Permissions']['sections']['Users with capabilities']['lines']

exclusions = []

clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Files readable by me and root / Readable files belonging to root and readable by me but not world readable
print("Readable files belonging to root and readable by me but not world readable")
root = c['Files with Interesting Permissions']['sections']['Readable files belonging to root and readable by me but not world readable']['lines']

exclusions = []

clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Wacky Files Matched for whatever reason / Searching root files in home dirs (limit 30)
print("Wacky Files Matched for whatever reason")
root = c['Files with Interesting Permissions']['sections']['Searching root files in home dirs (limit 30)']['lines']

exclusions = [
  r'^/home/$',
  r'^/var/www$',
  r'^/root/$',
  r'^/var/www/html$'
]

clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Unsuspected in /opt (usually empty)
print("Unsuspected in /opt")
root = c['Other Interesting Files']['sections']['Unexpected in /opt (usually empty)']['lines']

exclusions = [
  r'total \d+$',
  r'^\.$',
  r'^\.\.$',
]

clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Pkexec + Adm LPE check / Checking Pkexec policy

# Cron Jobs
print("Cron Jobs")
root = c['Processes, Crons, Timers, Services and Sockets']['sections']['Cron jobs']['lines']
exclusions = [
    r'root.*\.\.',
    r'root.*\.',
    r'root.*\.placeholder',
    r'root.*e2scrub_all',
    r'root.*man-db'
]

clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Processes, Crons, Services
#TODO These repeat in output. Fix that 
print('Procs')
root = c['Processes, Crons, Timers, Services and Sockets']['sections']['Running processes (cleaned)']['lines']

exclusions = []

clean = [item['clean_text'] for item in root if 'clean_text' in item]
for item in clean:
  print(item)
  exclusions.append(item)
sep()

# Systemd PATH
root = c['Processes, Crons, Timers, Services and Sockets']['sections']['Systemd PATH']['lines'][0]['clean_text']
print("systemd PATH")
print(root)
sep()

# Apache2 & Nginx Useful Files

# Apache2 TBD no sample ATM

#Nginx Config / "PHP exec extensions"
print("Nginx Config files")

root = c["Software Information"]['sections']['Analyzing Apache-Nginx Files (limit 70)']['sections']
if "PHP exec extensions" in root:
    root = root['PHP exec extensions']['lines']
    matches = [
        r'.*sites-enabled.*',
        r'.*server_name.*',   # Not removed
        r'.*listen.*',        # Not removed
        r'.*nginx\.conf.*',
        r'.*proxy_pass.*',    # Not removed
        r'.*access\.log.*',
        r'.*error\.log.*'
    ]
    
    clean = []
    for item in root:
        if 'clean_text' in item:
            text = item['clean_text']
            for match in matches[:]:
                if re.search(match, text):
                    clean.append(text)
                    if match not in [r'.*listen.*', r'.*server_name.*', r'.*proxy_pass.*']:
                        matches.remove(match)
                    break
    for item in clean:
        print(item)
    sep()

# Nginx Modules
print("Nginx Modules")
root = c["Software Information"]['sections']['Analyzing Apache-Nginx Files (limit 70)']['sections']
if "Nginx modules" in root:
  root = root['Nginx modules']['lines']
  clean = [item['clean_text'] for item in root]
  for item in range(len(clean)):
    print(clean[item])
  sep()


# MySQL Credentials / Searching mysql credentials and exec
print("MySQL Credentials")
root = c["Software Information"]['sections']['Searching mysql credentials and exec']['lines']
clean = [item['clean_text'] for item in root]
for item in range(len(clean)): 
  print(clean[item])
sep()

# SSH Files / Searching ssl/ssh files
print("SSH Files")
root = c["Software Information"]['sections']['Searching ssl/ssh files']['lines']
if len(root) != 0:
  clean = [item['clean_text'] for item in root]
  for item in range(len(clean)):
    print(clean[item])
sep()


# Useful software
print('Useful Software')
root = c["Software Information"]['sections']['Useful software']['lines']

exclusions = [
    r'.*curl$',
    r'.*base64$',
    r'.*ping$',
    r'.*perl$',
    r'.*python3$',
    r'.*sudo$',
    r'.*wget$'
]

clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Network Interfaces
print("Network Interfacess")
root = c['Network Information']['sections']['Interfaces']['lines']
matches = [r'\b(?:\d{1,3}\.){3}\d{1,3}\b']
clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and any(re.search(match, item['clean_text']) for match in matches)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Hostname, hosts and DNS
print("Hostname, hosts and DNS")
root = c['Network Information']['sections']['Hostname, hosts and DNS']['lines']
exclusions = [
    r'ip6-localhost',
    r'ip6-loopback',
    r'ip6-localnet',
    r'ip6-mcastprefix',
    r'ip6-allnodes',
    r'ip6-allrouters'
]
clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Active Ports
print("Active Ports TCPv4")
root = c['Network Information']['sections']['Active Ports']['lines']
exclusions = [r'.*tcp6.*']
clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Unmounted file-systems?
root = c['System Information']['sections']['Unmounted file-system?']['lines']
clean = [item['clean_text'] for item in root]
print("Unmounted file-systems?")
for item in range(len(clean)):
  print(clean[item])
sep()

# Can I sniff with tcpdump?
print("Can I sniff with tcpdump?")
root = c['Network Information']['sections']['Can I sniff with tcpdump?']['lines'][0]['clean_text']
print(root)
sep()

# Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
print("Check sudo -l, /etc/sudoers, and /etc/sudoers.d")
sep()

# Searching passwords in history files
print("Passwords in History Files")
root = c['Other Interesting Files']['sections']['Searching passwords in history files']['lines']
exclusions = []
clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Searching *password* or *credential* files in home (limit 70)
print("*password* or *credential* files")
root = c['Other Interesting Files']['sections']['Searching passwords in history files']['lines']
exclusions = [
  r'/usr/bin/systemd-ask-password',
  r'/usr/bin/systemd-tty-ask-password-agent',
  r'/usr/lib/git-core/git-credential',
  r'/usr/lib/git-core/git-credential-cache',
  r'/usr/lib/git-core/git-credential-cache--daemon',
  r'#)There are more creds/passwds files in the previous parent folder',
  r'/usr/lib/grub/i386-pc/password.mod',
  r'/usr/lib/grub/i386-pc/password_pbkdf2.mod',
  r'/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/management/jmxremote.password',
  r'/usr/lib/python3/dist-packages/keyring/__pycache__/credentials.cpython-310.pyc',
  r'/usr/lib/python3/dist-packages/keyring/credentials.py', 
  r'/usr/lib/python3/dist-packages/launchpadlib/.*',
  # r'/usr/lib/python3/dist-packages/launchpadlib/__pycache__/credentials.cpython-310.pyc',
  # r'/usr/lib/python3/dist-packages/launchpadlib/credentials.py',
  # r'/usr/lib/python3/dist-packages/launchpadlib/tests/__pycache__/test_credential_store.cpython-310.pyc',
  # r'/usr/lib/python3/dist-packages/launchpadlib/tests/test_credential_store.py',
  r'/usr/lib/python3/dist-packages/oauthlib/.*',
  r'/usr/lib/python3/dist-packages/twisted/.*',
  r'/usr/lib/systemd/system/.*'
  r'/usr/share/doc/git/contrib/credential/.*',
  r'/usr/share/icons/.*',
  r'/usr/share/man/.*',
  r'/usr/share/pam/.*',
  r'/var/cache/debconf/.*'
  r'/var/lib/cloud/instances/iid-datasource-none/sem/.*',
  r'/var/lib/pam/.*',
]

clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# Checking for TTY (sudo/su) passwords in audit logs
print("Checking for TTY (sudo/su) passwords in audit logs")
root = c['Other Interesting Files']['sections']['Checking for TTY (sudo/su) passwords in audit logs']['lines']

exclusions = []
clean = [item['clean_text'] for item in root 
         if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
for item in range(len(clean)):
  print(clean[item])
sep()

# General log files # Analyzing Interesting logs Files (limit 70)
print("All Log Files")
root = c["Software Information"]['sections']['Analyzing Interesting logs Files (limit 70)']['lines']
clean = [item['clean_text'] for item in root]
for item in range(len(clean)):
  print(clean[item])
sep()