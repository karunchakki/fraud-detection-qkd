# wsgi.py
# Entry point for WSGI servers (like Gunicorn or Waitress).
# It imports the Flask application instance 'app' from the main application file (app.py).

import os
from app import app # Import the configured Flask app instance

# --- Production Deployment Instructions ---
# Gunicorn (Linux/macOS):
#   gunicorn --bind 0.0.0.0:5000 wsgi:app
#
# Waitress (Windows/Cross-Platform):
#   waitress-serve --host 0.0.0.0 --port 5000 wsgi:app
#
# Make sure required environment variables (like FLASK_SECRET_KEY, MYSQL credentials)
# are set in the environment where the WSGI server runs.

if __name__ == "__main__":
    # This block is typically NOT executed by WSGI servers like Gunicorn/Waitress.
    # They directly import the 'app' object defined above.
    # However, running 'python wsgi.py' can be used for quick testing with Waitress.
    print("--- Running wsgi.py directly (for testing/dev only) ---")
    try:
        from waitress import serve
        # Use environment variables or defaults for host/port when run directly
        host = os.environ.get('FLASK_RUN_HOST', '127.0.0.1') # Default to localhost for direct run
        port = int(os.environ.get('FLASK_RUN_PORT', 5000)) # Default to 5000
        print(f"Attempting to start server with Waitress on http://{host}:{port}...")
        print("NOTE: For production, run 'waitress-serve ... wsgi:app' directly.")
        print("Ensure environment variables (DB credentials, SECRET_KEY) are set.")
        serve(app, host=host, port=port)
    except ImportError:
        print("\nWARNING: Waitress not found.")
        print("To run directly with Waitress: pip install waitress")
        print("Alternatively, run the Flask development server using: python app.py\n")
    except Exception as e:
        print(f"\nError attempting to run Waitress directly: {e}")
        print("You might want to run 'python app.py' instead for development.\n")
