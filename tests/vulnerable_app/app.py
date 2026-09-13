from flask import Flask, request, render_template_string

app = Flask(__name__)

# 1. Classic Reflected XSS (HTML Body)
@app.route('/search')
def search():
    q = request.args.get('q', '')
    return render_template_string(f"<h1>Search results for: {q}</h1>")

# 2. Attribute-based XSS
@app.route('/profile')
def profile():
    name = request.args.get('name', '')
    return render_template_string(f"<input type='text' value='{name}'>")

# 3. JS-based XSS
@app.route('/callback')
def callback():
    url = request.args.get('url', '')
    return render_template_string(f"<script>var redirectUrl = '{url}';</script>")

# 4. DOM-based XSS (Simulated by reflecting into a script that uses innerHTML)
@app.route('/dom')
def dom():
    q = request.args.get('q', '')
    return render_template_string(f"""
        <div id='result'></div>
        <script>
            var q = '{q}';
            document.getElementById('result').innerHTML = 'Search: ' + q;
        </script>
    """)

# 5. Stored XSS (Simulated with a global list)
STORED_DATA = []
@app.route('/post', methods=['POST'])
def post():
    msg = request.form.get('msg', '')
    STORED_DATA.append(msg)
    return "Posted!"

@app.route('/board')
def board():
    msgs = "".join([f"<div>{m}</div>" for m in STORED_DATA])
    return render_template_string(f"<h1>Message Board</h1>{msgs}")

if __name__ == "__main__":
    app.run(port=5000)
