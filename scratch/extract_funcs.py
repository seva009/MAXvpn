import re

with open('formatted1.js', 'r') as f:
    content = f.read()

keywords = ['hangup', 'endCall', 'decline', 'reject', 'leaveCall', 'terminate']
for kw in keywords:
    matches = re.finditer(rf'(?i){kw}', content)
    for m in matches:
        start = max(0, m.start() - 50)
        end = min(len(content), m.start() + 50)
        # Only print if it looks like a function call or definition with opcode, or just limit it
        # to avoid too much noise, just get unique matches around G(async or K(async
pass
