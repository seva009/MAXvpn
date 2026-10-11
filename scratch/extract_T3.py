import re

with open('formatted0.js', 'r') as f:
    content = f.read()

matches = re.finditer(r'(function|const|let)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z0-9_]+)\s*=>\s*\{[^}]*hangup|hangup[a-zA-Z0-9_]*\s*\(', content, re.IGNORECASE)
for m in matches:
    start = max(0, m.start() - 50)
    end = min(len(content), m.start() + 150)
    # print(content[start:end])
    pass

# We can search for what the sdk method is called
# e.g. "sdk.hangup" or "api.hangup"
idx = content.find('.hangup(')
if idx != -1:
    print(".hangup( found:")
    print(content[max(0, idx - 200):min(len(content), idx + 200)])

