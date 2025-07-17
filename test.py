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
