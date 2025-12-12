import unittest
import sys
import os

# Ensure we can import from the root directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app

class TestRoutes(unittest.TestCase):
    def setUp(self):
        # Configure app for testing
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        self.client = app.test_client()

    def test_health_endpoint(self):
        """Verify the /health endpoint returns 200 OK (or 503 if DB mock fails, but structure exists)."""
        response = self.client.get('/health')
        # We accept 200 or 503 depending on if the DB engine detects a real DB or not during test
        self.assertIn(response.status_code, [200, 503])
        self.assertIn(b'status', response.data)

    def test_login_route_exists(self):
        """Verify /login returns 200 OK and contains expected HTML."""
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        # Check for standard text usually found on login pages
        self.assertTrue(b'Login' in response.data or b'Sign In' in response.data)

    def test_register_url_building(self):
        """
        Verify url_for('register') works (The Fix).
        Verify url_for('register_customer') fails (confirming the old bug is gone).
        """
        with app.test_request_context():
            from flask import url_for
            
            # 1. This must work (The correct route name)
            try:
                url = url_for('register')
                self.assertEqual(url, '/register')
            except Exception as e:
                self.fail(f"url_for('register') failed: {e}")
            
            # 2. This must fail (The old incorrect name)
            with self.assertRaises(Exception):
                url_for('register_customer')

if __name__ == '__main__':
    unittest.main()
