import re

with open('formatted1.js', 'r') as f:
    content = f.read()

# Look for t(79,  and t(80,
for op in [77, 79, 80, 81, 82, 83, 136, 138, 142]:
    idx = content.find(f't({op},')
    if idx != -1:
        print(f"--- OPCODE {op} ---")
        start = max(0, idx - 150)
        end = min(len(content), idx + 200)
        print(content[start:end])

