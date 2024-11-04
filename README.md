# PEASS-Parsers

# "Installation"

## 1. Wget relevant parts

`wget https://github.com/ReKon64/PEAS-Parsers/blob/main/linj2read.py && https://github.com/ReKon64/PEAS-Parsers/blob/main/win2read.py && wget https://github.com/ReKon64/PEAS-Parsers/blob/main/peas2json/peas2json.py`

## 2. Git Clone whole repo
`https://github.com/ReKon64/PEAS-Parsers`

## Usage
### 0. Acquire some PEAS output
Doesn't matter if it's colored or not and if any results have been omitted.
It will error out if the file is malformed and the JSON parser fails to account for it

### 1. PEAS2JSON
Use the included peas2json copy that adds an all-important slash to one of the ANSI escape sequences.

Alternatively get `https://github.com/peass-ng/PEASS-ng/blob/master/parsers/peas2json.py` and fix it yourself.

I do not know if the powershell version works and I have no intention of supporting it.

`python3 peas2json.py peass.log peass.json`

### 2. JSON2READABLE
For Windows
`python3 win2read.py peass.json`

For Linux
`python3 lin2read.py peass.json`

### 3. Muh file
Since we're using `colorama` module for output, you can safely pipe `|` or redirect the output with `>`  `<`.

There will be no colours tho.

### 4. Regex
This project uses a pretty strict regex in mostly exclusion based logic, which means any deviation will be output.

If you see something regularly, just add it yourself or post an issue.

Don't know regex? Ask ChatGPT and go from there. It fails with more specific patterns though.

### 5. Your Linpeas parser code sucks !1@21!
Yes it does. I might fix it.

#### I might also package this in the future because dependency hell is not kewl.
