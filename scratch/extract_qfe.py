import re

with open('formatted1.js', 'r') as f:
    content = f.read()

# find "call:hotkey-hangup" usage
idx = content.find('"call:hotkey-hangup"')
if idx != -1:
    print(content[idx:idx+150])

# we also know QFe is the localized string. 
# let's grep for 'call:hotkey-hangup' in all files just in case.
