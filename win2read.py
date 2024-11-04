#!/usr/bin/env python3
import json
import re
from colorama import init, Fore, Style # Makes the output safe for redirection. Sadly this won't preserve the colours 
import sys
import argparse

#TODO
# Add a switch to ingest a winpeas output file and parse it via an included peas2json version
# So see licensing stuff for that
# Also maybe package it for internet cred lol

init(autoreset=True)

parser = argparse.ArgumentParser(
  prog = "win2read.py",
  description = "Process winpeas > peas2json > files into readable format",)
parser.add_argument('filepath', help = 'Path to winpeas json file to parse', action='store')
args = parser.parse_args()

with open(args.filepath, "r") as f:
  c = json.loads(f.read())

def sep():
  print(f"{Style.BRIGHT}{Fore.BLUE}-" * 40)

def bold(text):
  print(f"{Style.BRIGHT}{Fore.GREEN}{text}")

# # # # # # #
# root = json tree one layer before "clear_text", REQUIRED
# banner = should describe the section in short, ENCOURAGED
# prepend = array of regex literals to prepend to "exclusions" entries, OPTIONAL
# append = array of regex literals to append to "exclusions" entries  , OPTIONAL
# exclusions = array of regex literals,  OPTIONAL
# If match DO NOT print
# If only root provided, will simply print all clean_text entries
def exclude_extract(root, banner: str = "", prepend=[], append=[], exclusions=[]):
  
  if banner:
    bold(banner)
  else:
    pass

  if prepend or append:
    exclusions = [fr"{prepend}{pattern}{append}" for pattern in exclusions]
  
  if exclusions:
    clean = [item['clean_text'] for item in root 
      if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
    for item in range(len(clean)):
      print(clean[item])
    sep()
    #print(exclusions)

  else:
    clean = [item['clean_text'] for item in root]

    for item in range(len(clean)):
      print(clean[item])
    sep()

# # # # # # #
# root = json tree one layer before "clear_text", REQUIRED
# banner = should describe the section in short, ENCOURAGED
# prepend = array of regex literals to prepend to "matches" entries, OPTIONAL
# append = array of regex literals to append to "matches" entries  , OPTIONAL
# matches = array of regex literals, OPTIONAL
# If match print
# If only root provided, will simply print all clean_text entries
def match_extract(root, banner: str = "", prepend=[], append=[], matches=[]):

  if banner:
    bold(banner)
  else:
    pass

  if prepend or append:
    matches = [fr"{prepend}{pattern}{append}" for pattern in matches]

  if matches:
    clean = [item['clean_text'] for item in root 
            if 'clean_text' in item and any(re.search(match, item['clean_text']) for match in matches)]
    for item in range(len(clean)):
      print(clean[item])
    sep()

  else:
    clean = [item['clean_text'] for item in root]

    for item in range(len(clean)):
      print(clean[item])
    sep()

#Starting Separator for lookz
sep()

#System Information - Basic system information
exclude_extract(
  banner = "Basic system information",
  root = c['System Information']['sections']['Basic System Information']['lines'],
  exclusions = [
    r'ProductName',
    r'EditionID',
    r'BuildBranch',
    r'Architecture',
    r'ProcessorCount',
    r'SystemLang',
    r'KeyboardLang',
    r'TimeZone',
    r'IsVirtualMachine',
    r'Current Time',
    r'HighIntegrity',
  ],
)

#Users Information - Users (Current User & Groups)
match_extract(
  banner = "Current User & Groups",
  root = c['Users Information']['sections']['Users']['lines'],
  matches = [
    r'Current user:',
    r'Current groups:',
  ],
)

#Users Information - Current Token privileges
exclude_extract(
  banner = "Current Privileges",
  root = c['Users Information']['sections']['Current Token privileges']['lines'],
  exclusions = [
  ]
)

#Network Information - Host File
exclude_extract(
  banner = "Hosts File",
  root = c['Network Information']['sections']['Host File']['lines'],
)

#Network Information - Current TCP Listening Ports
exclude_extract(
  banner = "Current TCP Listening Ports",
  root = c['Network Information']['sections']['Current TCP Listening Ports']['lines'],
  exclusions = [
    r'[::]',
    r'Enumerating IPv6 connections',

    # Dirty IPv6 column filter thanks to different whitespace length 
    # compared to IPv4 
    r'Protocol   Local Address                               Local Port    Remote Address                              Remote Port     State             Process ID      Process Name',
  ]
)

#System Information - Checking AlwaysInstallElevated
match_extract(
  banner = "Checking AlwaysInstallElevated",
  root = c['System Information']['sections']['Checking AlwaysInstallElevated']['lines'],
  matches = []
)

#Users Information - Looking for AutoLogon credentials
exclude_extract(
  banner = "AutoLogon Creds in Registry",
  root = c['Users Information']['sections']['Looking for AutoLogon credentials']['lines'],
  exclusions = []
)

#System Information - Installed .NET versions
match_extract(
  banner = "Installed .NET versions",
  root = c['System Information']['sections']['Installed .NET versions']['lines'],
  matches = [
    r'2',
    r'4',
    r'5',
  ]
)

#System Information - Showing All Microsoft Updates 
# No data Sample Empty no way to design
# "[X] Exception: Exception has been thrown by the target of an invocation."
exclude_extract(
  banner = "All Microsoft Updates",
  root = c['System Information']['sections']['Showing All Microsoft Updates']['lines'],
  exclusions = [],
)

#Browsers Information - Looking for Firefox DBs
exclude_extract(
  banner = "FFox DBs",
  root = c['Browsers Information']['sections']['Looking for Firefox DBs']['lines'],
)

#Browsers Information - Looking for Chrome DBs
exclude_extract(
  banner = "Chrome DBs",
  root = c['Browsers Information']['sections']['Looking for Chrome DBs']['lines'],
)

#Installed Applications --Via Program Files/Uninstall registry--
exclude_extract(
  banner = "Installed Applications Via Program Files/Uninstall registry",
  root = c['Applications Information']['sections']['Installed Applications --Via Program Files/Uninstall registry--']['lines'],
  exclusions = [
    r'C:\\Program Files\\Common Files$',
    r'C:\\Program Files\\desktop.ini$',
    r'C:\\Program Files\\Microsoft Update Health Tools',
    r'C:\\Program Files\\ModifiableWindowsApps',
    r'C:\\Program Files\\Uninstall Information',
    r'C:\\Program Files\\VMware',
    r'C:\\Program Files\\Windows Defender',
    r'C:\\Program Files\\Windows Defender Advanced Threat Protection',
    r'C:\\Program Files\\Windows Mail',
    r'C:\\Program Files\\Windows Media Player',
    r'C:\\Program Files\\Windows Multimedia Platform',
    r'C:\\Program Files\\Windows NT',
    r'C:\\Program Files\\Windows Photo Viewer',
    r'C:\\Program Files\\Windows Portable Devices',
    r'C:\\Program Files\\Windows Security',
    r'C:\\Program Files\\Windows Sidebar',
    r'C:\\Program Files\\WindowsApps',
    r'C:\\Program Files\\WindowsPowerShell',
    r'C:\\Windows\\System32$',
  ],
)

#Interesting files and registry - Putty Sessions
exclude_extract(
  banner = "Putty Sessions",
  root = c['Interesting files and registry']['sections']['Putty Sessions']['lines']
)

#Interesting files and registry - Putty SSH Host keys
exclude_extract(
  banner = "Putty SSH Keys",
  root = c['Interesting files and registry']['sections']['Putty SSH Host keys']['lines']
)

#Interesting files and registry - Unattend Files
exclude_extract(
  banner = "Unattended Installation Files",
  root = c['Interesting files and registry']['sections']['Unattend Files']['lines'],
  exclusions = [
    r'<Password>\*SENSITIVE\*DATA\*DELETED\*</Password>',
  ]
)

#Interesting files and registry - Looking for common SAM & SYSTEM backups
exclude_extract(
  banner = "Common SAM and SYSTEM backup locations",
  root = c['Interesting files and registry']['sections']['Looking for common SAM & SYSTEM backups']['lines']
)

#Interesting files and registry - Looking for McAfee Sitelist.xml Files
exclude_extract(
  banner = "McAfee Sitelist.xml Files",
  root = c['Interesting files and registry']['sections']['Looking for McAfee Sitelist.xml Files']['lines']
)

#Non MS Services - This filter might miss vulnerable Drivers
exclude_extract(
  banner = "Non MS Services - This filter might miss vulnerable Drivers",
  root = c['Services Information']['sections']['Interesting Services -non Microsoft-']['lines'],
  exclusions = [
    r'.*VMWare.*',
    r'.*VMware.*',
    r'.*System32/drivers.*',
    r'.* - System$',
    r'.*Intel.*',
    r'=================================================================================================',
    r'.* - Boot$',
    r'Alias Manager and Ticket Service',
    r'Driver to provide enhanced memory management of this virtual machine.',
    r'Provides support for synchronizing objects between the host and guest operating systems.',
    r'vSockets Driver',
    r'Generic driver for USB devices',
  ]
)

#Services Information - Modifiable Services
exclude_extract(
  banner = "Modifiable Services",
  root = c['Services Information']['sections']['Modifiable Services']['lines'],
  exclusions = []
)

#Services Information - Looking if you can modify any service registry
exclude_extract(
  banner = "Any modifiable any service registry",
  root = c['Services Information']['sections']['Looking if you can modify any service registry']['lines'],
  exclusions = []
)

#Services Information - Checking write permissions in PATH folders (DLL Hijacking)
match_extract(
  banner = "Common False Positives for DLL Hijacking via write perms",
  root = c['Services Information']['sections']['Checking write permissions in PATH folders (DLL Hijacking)']['lines'],
  matches = [
    r'(DLL Hijacking)',
  ]
)

#System Information - Checking KrbRelayUp
match_extract(
  banner = "Checking KrbRelayUp",
  root = c['System Information']['sections']['Checking KrbRelayUp']['lines'],
  matches = [],
)

#Windows Credentials - Looking for Kerberos tickets
exclude_extract(
  banner = "Any Stored Kerberos Tickets",
  root = c['Windows Credentials']['sections']['Looking for Kerberos tickets']['lines'],
  exclusions = [],
)

#System Information - User Environment Variables
exclude_extract(
  banner = "User Environment Variables",
  root = c['System Information']['sections']['User Environment Variables']['lines'],
  exclusions = [
    r'COMPUTERNAME',
    r'PSModulePath',
    r'PROCESSOR_ARCHITECTURE',
    r'CommonProgramFiles',
    r'ProgramFiles(x86)',
    r'PROCESSOR_LEVEL',
    r'ProgramFiles',
    r'USERPROFILE',
    r'SystemRoot',
    r'ALLUSERSPROFILE',
    r'DriverData',
    r'ProgramData',
    r'PROCESSOR_REVISION',
    r'CommonProgramW6432',
    r'OneDrive',
    r'CommonProgramFiles',
    r'OS:',
    r'PROCESSOR_IDENTIFIER:',
    r'ComSpec:',
    r'PROMPT:',
    r'NUMBER_OF_PROCESSORS:',
    r'APPDATA:',
    r'TMP',
    r'ProgramW6432:',
    r'windir:',
  ],
)

#System Information - System Environment Variables
exclude_extract(
  banner = "System Environment Variables",
  root = c['System Information']['sections']['System Environment Variables']['lines'],
  exclusions = [
    r'ComSpec:',
    r'DriverData:',
    r'NUMBER_OF_PROCESSORS:',
    r'OS:',
    r'PROCESSOR_ARCHITECTURE:',
    r'PROCESSOR_IDENTIFIER:',
    r'PROCESSOR_LEVEL:',
    r'PROCESSOR_REVISION:',
    r'PSModulePath:',
    r'TEMP:',
    r'TMP:',
    r'USERNAME:',
    r'windir:',
  ],
)

#System Information - PowerShell Settings
match_extract(
  banner = "PowerShell Settings",
  root = c['System Information']['sections']['PowerShell Settings']['lines'],
  matches = [
    r'PowerShell v2 Version:',
    r'PowerShell v5 Version:',
    r'PS history file:',
  ],
)

#System Information - Audit Settings
exclude_extract(
  banner = "Audit Settings",
  root = c['System Information']['sections']['Audit Settings']['lines'],
  exclusions = [],
)

#System Information - AV Information
match_extract(
  banner = "AV Information",
  root = c['System Information']['sections']['AV Information']['lines'],
  matches = [
    r'Name:',
    r'ProductEXE:',
  ],
)

#System Information - UAC Status
exclude_extract(
  banner = "UAC Settings",
  root = c['System Information']['sections']['UAC Status']['lines'],
  exclusions = [
    r'LocalAccountTokenFilterPolicy:',
    r'EnableLUA', # This one might be useful in more advanced scenarios but ehhh
  ]
)

#Additional Hints
bold('Check C:\ for weird Folders')
bold('Run systeminfo and wes-ng.py')