import re

with open('formatted0.js', 'r') as f:
    content = f.read()

# search for how the hangup payload is constructed in WebRTC signaling
idx = content.find('.hangup(n)')
if idx != -1:
    print(content[max(0, idx - 400):min(len(content), idx + 200)])
else:
    # search for send.*hangup
    pass
