import re

with open('formatted0.js', 'r') as f:
    content = f.read()

# search for "sa("
matches = re.finditer(r'\bsa\s*\(', content)
for m in matches:
    print(content[max(0, m.start() - 100):min(len(content), m.start() + 200)])
    print("-------")
