# wsgi.py
# Entry point for WSGI servers (like Gunicorn or Waitress).

# Ensure necessary modules can be found, especially if project structure is complex
# import sys
# import os
# sys.path.insert(0, os.path.dirname(__file__))

from app import app # Import the configured Flask app instance

# When run via 'waitress-serve wsgi:app', it directly uses the 'app' object.
# The block below is only for running 'python wsgi.py' for quick testing.
if __name__ == "__main__":
    print("--- Running wsgi.py directly (for testing/dev only) ---")
    try:
        from waitress import serve
        host = os.environ.get('FLASK_RUN_HOST', '127.0.0.1') # Default to localhost
        port = int(os.environ.get('FLASK_RUN_PORT', 5001)) # Use same port as app.py
        print(f"Attempting to start server with Waitress on http://{host}:{port}...")
        print("NOTE: For production, run 'waitress-serve ... wsgi:app' directly.")
        serve(app, host=host, port=port, threads=6) # Use Waitress to serve
    except ImportError:
        print("\nWARNING: Waitress not found. Cannot run directly.")
        print("To run directly with Waitress: pip install waitress")
        print("Alternatively, run the Flask development server using: python app.py\n")
    except Exception as e:
        print(f"\nError attempting to run Waitress directly: {e}")
        print("Consider running 'python app.py' instead for development.\n")
