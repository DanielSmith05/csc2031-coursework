from config import app
from flask import render_template
from werkzeug.exceptions import TooManyRequests


@app.route('/')
def index():
    return render_template('home/index.html')

@app.errorhandler(TooManyRequests)
def rate_limit_error(e):
    return render_template('errors/rate_error.html'), 429

if __name__ == '__main__':
    app.run()