from config import app
from flask import render_template
from werkzeug.exceptions import TooManyRequests


@app.route('/')
def index():
    return render_template('home/index.html')

@app.errorhandler(TooManyRequests)
def rate_limit_error(e):
    return render_template('errors/rate_error.html'), 429

@app.errorhandler(400)
def bad_request(error):
    return render_template('errors/error.html', error_code=400, error_message="Bad Request",
                           description="The server could not understand the request due to invalid syntax."), 400

@app.errorhandler(404)
def not_found(error):
    return render_template('errors/error.html', error_code=404, error_message="Not Found",
                           description="The requested url could not be found, please navigate the home menu for necessary links."), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('errors/error.html', error_code=500, error_message="Internal Server Error",
                           description="The server encountered an internal error and was unable to complete your request."), 500

@app.errorhandler(501)
def not_implemented(error):
    return render_template('errors/error.html', error_code=501, error_message="Not Implemented",
                           description="The server does not recognize the request method or lacks the ability to fulfill it."), 501

if __name__ == '__main__':
    app.run()