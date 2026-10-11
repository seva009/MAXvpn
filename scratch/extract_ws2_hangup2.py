import re

with open('formatted1.js', 'r') as f:
    content = f.read()

# Let's search for hangup type commands
matches = re.finditer(r'command[^\w]*hangup', content, re.IGNORECASE)
for m in matches:
    print(content[max(0, m.start() - 150) : min(len(content), m.start() + 150)])
    print("-------")
