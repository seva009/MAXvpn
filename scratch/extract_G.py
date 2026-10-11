import re

with open('formatted1.js', 'r') as f:
    content = f.read()

# find G(async ...
idx = 0
while True:
    idx = content.find('G(async', idx)
    if idx == -1:
        break
    # capture up to next '}))' or some reasonable length
    start = max(0, idx - 50)
    end = min(len(content), idx + 500)
    snippet = content[start:end]
    
    if '158' in snippet or '78' in snippet or '79' in snippet or '80' in snippet or '136' in snippet or '137' in snippet:
        print(f"--- MATCH at {idx} ---")
        print(snippet[:300])
        print("...")
        
    idx += 1

