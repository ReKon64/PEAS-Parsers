#!/usr/bin/env python3
import json
import re


#TODO, add argv boiler-plate for accepting infiles
# If you want an outfile just redirect ">" smh 
with open("/home/rekon/json2read/win2read/win.json", "r") as f:
  c = json.loads(f.read())

def sep():
  print("-" * 40)

# root = json tree one layer before "clear_text", REQUIRED
# prepend = array of regex literals to prepend to "exclusions" entries, OPTIONAL
# append = array of regex literals to append to "exclusions" entries  , OPTIONAL
# exclusions = array of regex literals,  OPTIONAL
# If match DO NOT print
# If only root provided, will simply print all clean_text entries
def exclude_extract(root, prepend=[], append=[], exclusions=[]):
  
  if prepend or append:
    exclusions = [fr"{prepend}{pattern}{append}" for pattern in exclusions]
  
  if exclusions:
    clean = [item['clean_text'] for item in root 
      if 'clean_text' in item and not any(re.search(exclusion, item['clean_text']) for exclusion in exclusions)]
    for item in range(len(clean)):
      print(clean[item])
    sep()
  
  else:
    clean = [item['clean_text'] for item in root]

    for item in range(len(clean)):
      print(clean[item])
    sep()


# root = json tree one layer before "clear_text", REQUIRED
# prepend = array of regex literals to prepend to "matches" entries, OPTIONAL
# append = array of regex literals to append to "matches" entries  , OPTIONAL
# matches = array of regex literals, OPTIONAL
# If match print
# If only root provided, will simply print all clean_text entries
def match_extract(root, prepend=[], append=[], matches=[]):

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

#Banner
sep()

#Basic system information
exclude_extract(
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

#Showing All Microsoft Updates - No data Sample Empty no way to design
# "[X] Exception: Exception has been thrown by the target of an invocation."
exclude_extract(
  root = c['System Information']['sections']['Showing All Microsoft Updates']['lines'],
  exclusions = [],
)

#User Environment Variables
exclude_extract(
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

#System Environment Variables
