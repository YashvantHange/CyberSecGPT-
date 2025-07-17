import requests

url = "http://127.0.0.1:5000/chat"
data = {"message": "Hello, can you help with cybersecurity?"}

response = requests.post(url, json=data)

# Debug output
print("STATUS CODE:", response.status_code)
print("RAW RESPONSE TEXT:", response.text)

# Then try parsing JSON
try:
    print("JSON:", response.json())
except Exception as e:
    print("Error parsing JSON:", e)

#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")  # 🔑 Replace with your key
