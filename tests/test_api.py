import unittest
from app import create_app, db
from app.models import Role, User
from base64 import b64encode
from flask import json


class ApiTestCase(unittest.TestCase):

    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        Role.insert_roles()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _get_api_headers(self, username, password):
        return {
            'Authorization': 'Basic ' + b64encode((username + ':' + password).encode('utf8')).decode('utf8'),
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def test_no_auth(self):
        response = self.client.get('/api/v1/posts/', content_type='application/json')
        self.assertEqual(response.status_code, 401)

    def test_posts(self):
        u = User(email='john@example.com', password='cat', confirmed=True)
        db.session.add(u)
        db.session.commit()

        response = self.client.post('/api/v1/posts/',
                                    headers=self._get_api_headers('john@example.com', 'cat'),
                                    data=json.dumps({'body': 'It is the *body* of my post'}))
        self.assertEqual(response.status_code, 201)
        url = response.headers.get('Location')
        self.assertIsNotNone(url)

        response = self.client.get(url, headers=self._get_api_headers('john@example.com', 'cat'))
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response.get('body'), 'It is the *body* of my post')
        self.assertEqual('http://localhost' + json_response.get('url'), url)
        self.assertEqual(json_response.get('body_html'), '<p>It is the <em>body</em> of my post</p>')
