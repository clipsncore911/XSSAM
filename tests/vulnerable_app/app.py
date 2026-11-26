"""Deliberately vulnerable local test application.

Never expose this app on a public interface. It is provided only so that the
scanner can be exercised against a target you control.
"""

from html import escape

from flask import Flask, Response, request

app = Flask(__name__)
STORED_DATA: list[str] = []


def html_response(body: str, status: int = 200) -> Response:
    return Response(body, status=status, content_type="text/html; charset=utf-8")


@app.route("/")
def index() -> Response:
    return html_response(
        """
        <h1>XSSAM local test target</h1>
        <ul>
          <li><a href="/search?q=hello">Reflected HTML context</a></li>
          <li><a href="/profile?name=guest">Attribute context</a></li>
          <li><a href="/callback?url=/">JavaScript context</a></li>
          <li><a href="/dom">DOM sink</a></li>
          <li><a href="/escaped?q=hello">HTML-escaped (safe)</a></li>
          <li><a href="/deep">Depth-limited page</a></li>
          <li><a href="https://example.invalid">Out-of-scope link</a></li>
        </ul>
        <form action="/post" method="post">
          <input name="msg" value="hello">
          <button type="submit">Post</button>
        </form>
        """
    )


@app.route("/search")
def search() -> Response:
    q = request.args.get("q", "")
    # Intentionally unescaped: reflected XSS test case.
    return html_response(f"<h1>Search results for: {q}</h1>")


@app.route("/profile")
def profile() -> Response:
    name = request.args.get("name", "")
    # Intentionally unescaped: attribute-breakout test case.
    return html_response(f"<input type='text' value='{name}'>")


@app.route("/callback")
def callback() -> Response:
    url = request.args.get("url", "")
    # Intentionally unescaped: JavaScript-string test case.
    return html_response(f"<script>var redirectUrl = '{url}';</script>")


@app.route("/dom")
def dom() -> Response:
    return html_response(
        """
        <div id='result'></div>
        <script>
          document.getElementById('result').innerHTML =
            decodeURIComponent(location.hash.slice(1));
        </script>
        """
    )


@app.route("/escaped")
def escaped() -> Response:
    q = request.args.get("q", "")
    return html_response(f"<h1>Search results for: {escape(q)}</h1>")


@app.route("/item/<item_id>")
def item(item_id: str) -> Response:
    return html_response(f"<h1>Item: {escape(item_id)}</h1>")


@app.route("/deep")
def deep() -> Response:
    return html_response('<a href="/too-deep">One level deeper</a>')


@app.route("/too-deep")
def too_deep() -> Response:
    return html_response("<h1>Beyond the default crawl depth</h1>")


@app.route("/post", methods=["POST"])
def post() -> Response:
    msg = request.form.get("msg", "")
    STORED_DATA.append(msg)
    # Intentionally unescaped: reflected POST body test case.
    return html_response(f"<div id='result'>{msg}</div>")


@app.route("/board")
def board() -> Response:
    messages = "".join(f"<div>{msg}</div>" for msg in STORED_DATA)
    return html_response(f"<h1>Message Board</h1>{messages}")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
