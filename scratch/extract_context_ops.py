import re

with open('formatted1.js', 'r') as f:
    content = f.read()

for op in [166, 167, 84, 102, 69, 76, 78]:
    matches = re.finditer(rf'\(\s*{op}\s*,', content)
    for m in matches:
        print(f"--- OPCODE {op} ---")
        start = max(0, m.start() - 250)
        end = min(len(content), m.start() + 250)
        print(content[start:end])

