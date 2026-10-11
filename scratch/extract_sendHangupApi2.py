import re

with open('formatted0.js', 'r') as f:
    content = f.read()

matches = re.finditer(r'_sendHangupApi(?:[\s\(]|=)', content)
for m in matches:
    print(content[max(0, m.start() - 100):min(len(content), m.start() + 300)])
    print("-------")

