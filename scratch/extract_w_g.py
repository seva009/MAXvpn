import re

with open('formatted0.js', 'r') as f:
    content = f.read()

# For formatted0.js-51900
idx = content.find('"call:hangup": w')
start = max(0, idx - 1000)
end = min(len(content), idx + 200)
print("--- w handler ---")
print(content[start:end])

# For formatted0.js-40760
idx = content.find('"call:hangup": g')
start = max(0, idx - 1000)
end = min(len(content), idx + 200)
print("--- g handler ---")
print(content[start:end])

