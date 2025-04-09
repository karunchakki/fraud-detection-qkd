# wsgi.py
# This file acts as the entry point for WSGI servers like Waitress or Gunicorn.
# It imports the Flask application instance from your main app file.

from app import app

if __name__ == "__main__":
     # This block is usually NOT executed when run by Waitress/Gunicorn,
     # but it's here for completeness or potential direct execution tests.
     print("This script is intended to be run with a WSGI server.")
     print("Example using Waitress (Windows):")
     print("  waitress-serve --host 127.0.0.1 --port=5000 wsgi:app")
     # You could optionally add app.run() below for basic development testing,
     # but ensure it's removed or conditional for production/Waitress use.
     # print("Starting Flask development server (for direct wsgi.py run)...")
     # app.run(host='127.0.0.1', port=5000, debug=False) # Use debug=False if uncommented
