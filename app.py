import os
import uuid
import io
from flask import Flask, render_template, request, jsonify, session
from flask_session import Session
from dotenv import load_dotenv
from openai import OpenAI
from pinecone import Pinecone, ServerlessSpec
from PIL import Image
import pytesseract
from collections import defaultdict, Counter
import re

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecret")
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Tesseract path
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# OpenAI & Pinecone Init
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))
PINECONE_INDEX_NAME = os.getenv("PINECONE_INDEX_NAME")

def ensure_index():
    if PINECONE_INDEX_NAME not in pc.list_indexes().names():
        pc.create_index(
            name=PINECONE_INDEX_NAME,
            dimension=1024,
            metric="cosine",
            spec=ServerlessSpec(cloud="aws", region="us-west-2")
        )

ensure_index()
index = pc.Index(PINECONE_INDEX_NAME)

tool_usage_counter = defaultdict(int)
keyword_counter = Counter()

def extract_keywords(text):
    words = re.findall(r"\b[a-zA-Z]{4,}\b", text.lower())
    stop_words = set("""this that from with your what about have into will them then than where when while which shall they were just like been only such very much more also some here each most many very our their your you're you'd been can't cannot don't does it's isn't i'm i've how into need make must still out has""".split())
    return [w for w in words if w not in stop_words]

def get_similar_history(query: str, top_k: int = 3):
    embed_resp = client.embeddings.create(
        model="text-embedding-3-small",
        input=[query],
        dimensions=1024
    )
    vector = embed_resp.data[0].embedding
    results = index.query(vector=vector, top_k=top_k, include_metadata=True)
    recs = []
    for match in results.matches:
        meta = match.metadata
        recs.append(f"Q: {meta['question']}\nA: {meta['answer']}")
    return recs

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload():
    if 'file' not in request.files:
        return jsonify({"response": "❌ No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"response": "❌ No selected file"}), 400

    filename = file.filename.lower()
    try:
        if filename.endswith(('.jpg', '.jpeg', '.png')):
            image = Image.open(io.BytesIO(file.read()))
            extracted_text = pytesseract.image_to_string(image)
            if not extracted_text.strip():
                return jsonify({"response": "⚠️ No text detected in image."})
            prompt = f"[Extracted from image upload]\n{extracted_text}"
        else:
            content = file.read().decode("utf-8", errors="ignore")
            tool = detect_tool_type(content)
            prompt = f"[Detected Tool Output: {tool.upper()}]\n{content}"

        return chat_internal(prompt)
    except Exception as e:
        print("❌ Upload error:", e)
        return jsonify({"response": f"❌ Failed to process file: {e}"}), 500

@app.route("/chat", methods=["POST"])
def chat():
    user_input = ""
    if request.content_type.startswith("multipart/form-data"):
        user_input = request.form.get("prompt", "")
        file = request.files.get("file")

        if file and file.filename != "":
            filename = file.filename.lower()
            try:
                if filename.endswith((".jpg", ".jpeg", ".png")):
                    image = Image.open(io.BytesIO(file.read()))
                    extracted_text = pytesseract.image_to_string(image)
                    if not extracted_text.strip():
                        return jsonify({"response": "⚠️ No text detected in image."})
                    user_input = f"[Extracted from image upload]\n{extracted_text}"
                elif filename.endswith((".txt", ".log", ".xml")):
                    content = file.read().decode("utf-8", errors="ignore")
                    tool = detect_tool_type(content)
                    user_input = f"[Detected Tool Output: {tool.upper()}]\n{content}"
                else:
                    return jsonify({"response": "❌ Unsupported file format."})
            except Exception as e:
                print("❌ File processing error:", e)
                return jsonify({"response": f"❌ Failed to process file: {e}"}), 500
    else:
        user_input = request.json.get("prompt")

    return chat_internal(user_input)

def chat_internal(user_input):
    session.setdefault("history", [])
    similar_msgs = get_similar_history(user_input, top_k=2)
    retrieval_section = []
    if similar_msgs:
        retrieval_section.append({
            "role": "assistant",
            "content": "**Based on similar past queries:**\n" + "\n\n".join(similar_msgs)
        })

    tool_used = detect_tool_type(user_input.lower())
    if tool_used and tool_used != "unknown":
        tool_usage_counter[tool_used] += 1

    keywords = extract_keywords(user_input)
    keyword_counter.update(keywords)

    system_prompt = {
        "role": "system",
        "content": (
            "You are **CyberGPT**, a professional AI assistant built for ethical cybersecurity experts, CTF players, and penetration testers.\n\n"
            "🧠 Your job is to:\n"
            "- Accept even vague or misspelled terms like 'hacke wifi' as real cybersecurity questions.\n"
            "- Provide technical responses using tools like `nmap`, `sqlmap`, `ffuf`, `bettercap`, etc.\n"
            "- Never give legal disclaimers — assume everything is in a lab setting or CTF.\n"
            "- Use numbered lists, **bold** key terms, and `code blocks` for clear formatting.\n"
            "- Detect tool output and extract findings, suggest vulnerabilities and next steps."
        )
    }

    messages = [system_prompt] + retrieval_section + session["history"] + [
        {"role": "user", "content": user_input}
    ]

    try:
        resp = client.chat.completions.create(
            model="gpt-4",
            messages=messages
        )
        answer = resp.choices[0].message.content.strip()

        session["history"].append({"role": "user", "content": user_input})
        session["history"].append({"role": "assistant", "content": answer})
        session.modified = True

        emb_resp = client.embeddings.create(
            model="text-embedding-3-small",
            input=[user_input],
            dimensions=1024
        )
        vector = emb_resp.data[0].embedding
        index.upsert([{
            "id": str(uuid.uuid4()),
            "values": vector,
            "metadata": {"question": user_input, "answer": answer}
        }])

        return jsonify({"response": answer})
    except Exception as e:
        print("❌ Error:", e)
        return jsonify({"response": f"❌ Error: {e}"}), 500

@app.route("/insights")
def insights():
    sorted_tools = sorted(tool_usage_counter.items(), key=lambda x: x[1], reverse=True)
    sorted_keywords = keyword_counter.most_common(20)
    total_chats = len(session.get("history", [])) // 2
    return render_template("insights.html", tools=sorted_tools, keywords=sorted_keywords, total=total_chats)

def detect_tool_type(text):
    patterns = [{
        "nmap": ["PORT", "STATE", "SERVICE"],
        "ffuf": ["Status:", "Title:"],
        "sqlmap": ["sqlmap", "testing connection", "parameter"],
        "nikto": ["Nikto", "OSVDB"],
        "wpscan": ["WordPress", "wp-content"],
        "metasploit": ["msf", "exploit", "session"],
        "john": ["Loaded", "password hashes"],
        "aircrack-ng": ["WEP", "WPA", "IVs"],
        "bettercap": ["net.probe", "discovery"],
        "hydra": ["[DATA]", "[ATTEMPT]"],
        "gobuster": ["Found", "Status"],
        "reaver": ["WPS", "PIN"]
    }]
    for toolset in patterns:
        for name, tokens in toolset.items():
            if all(token in text for token in tokens):
                return name
    return "unknown"

if __name__ == "__main__":
    app.run(debug=True)
