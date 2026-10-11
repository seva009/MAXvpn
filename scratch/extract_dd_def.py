import re

with open('formatted0.js', 'r') as f:
    content = f.read()

matches = re.finditer(r'(function|const|let)\s+DD\s*=\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z0-9_]+)\s*=>\s*\{', content)
for m in matches:
    print(content[max(0, m.start() - 100):min(len(content), m.start() + 400)])
    print("-------")

# also try function DD
idx = content.find('function DD(')
if idx != -1:
    print("Found function DD:")
    print(content[max(0, idx - 100):min(len(content), idx + 400)])

