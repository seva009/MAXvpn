import re

with open('formatted1.js', 'r') as f:
    content = f.read()

idx = content.find('return yield* t(84, {')
if idx != -1:
    start = max(0, idx - 500)
    end = min(len(content), idx + 200)
    print(content[start:end])

