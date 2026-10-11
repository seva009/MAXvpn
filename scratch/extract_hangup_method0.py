import re

with open('formatted0.js', 'r') as f:
    content = f.read()

matches = re.finditer(r'hangup\s*\(', content)
for m in matches:
    print(content[max(0, m.start() - 200):min(len(content), m.start() + 800)])
    print("-------")

