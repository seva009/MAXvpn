import re

with open('formatted1.js', 'r') as f:
    content = f.read()

# Let's find all occurrences of 137 in the text and context
idx = 0
while True:
    idx = content.find('137', idx)
    if idx == -1:
        break
    start = max(0, idx - 100)
    end = min(len(content), idx + 100)
    snippet = content[start:end]
    if 'case' in snippet or 'opcode' in snippet or '158' in snippet or '78' in snippet:
        print(f"--- MATCH at {idx} ---")
        print(snippet)
    idx += 1

