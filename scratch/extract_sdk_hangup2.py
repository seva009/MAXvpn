import re

with open('formatted1.js', 'r') as f:
    content = f.read()

matches = re.finditer(r'hangup\([^)]*\)\s*\{', content)
for m in matches:
    print(content[max(0, m.start() - 150):min(len(content), m.start() + 400)])
    print("-------")
