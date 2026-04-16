from flask import Flask, render_template, request
import io, sys, os
from contextlib import redirect_stdout
import web_safety

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    out = ""
    if request.method == 'POST':
        url = request.form.get('url')
        f = io.StringIO()
        with redirect_stdout(f):
            web_safety.oday_final_shield(url)
        out = f.getvalue()
    return render_template('index.html', output=out)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
