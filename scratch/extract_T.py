import re

with open('formatted0.js', 'r') as f:
    content = f.read()

idx = content.find('onHangup: () => T(R(t))')
start = max(0, idx - 1000)
end = min(len(content), idx + 2000)
print(content[start:end])

