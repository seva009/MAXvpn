import re

with open('formatted1.js', 'r') as f:
    content = f.read()

# Let's search for HANGUP
matches = re.finditer(r'HANGUP', content)
for m in matches:
    print(content[max(0, m.start() - 150) : min(len(content), m.start() + 150)])
    print("-------")
