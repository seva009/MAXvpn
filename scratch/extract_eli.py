import re

with open('formatted1.js', 'r') as f:
    content = f.read()

for func in ['eli =', 'ili =', 'tli =']:
    idx = content.find(func)
    if idx != -1:
        print(f"--- {func} ---")
        start = max(0, idx - 50)
        end = min(len(content), idx + 500)
        print(content[start:end])

