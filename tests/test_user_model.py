import unittest
from app.models import User, Permission, AnonymousUser, Role, Follow
from app import db, create_app
import time
from datetime import datetime


class UserModelTestCase(unittest.TestCase):

    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        Role.insert_roles()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_password_setter(self):
        u = User(password='cat')
        self.assertTrue(u.password_hash is not None)

    def test_no_password_getter(self):
        u = User(password='cat')
        with self.assertRaises(AttributeError):
            u.password

    def test_verify_password(self):
        u = User(password='cat')
        self.assertTrue(u.verify_password('cat'))
        self.assertFalse(u.verify_password('dog'))

    def test_random_salt(self):
        u = User(password='cat')
        u2 = User(password='cat')
        self.assertTrue(u.password_hash != u2.password_hash)

    def test_valid_confirmation_token(self):
        u = User(password='bonobo')
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token()
        self.assertTrue(u.confirm_user(token))

    def test_invalid_confirmation_token(self):
        u = User(password='bonobo')
        u2 = User(password='orangutan')
        db.session.add_all([u, u2])
        db.session.commit()
        token = u.generate_confirmation_token()
        self.assertFalse(u2.confirm_user(token))

    def test_expired_confirmation_token(self):
        u = User(password='bonobo')
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token(expiration=1)
        time.sleep(2)
        self.assertFalse(u.confirm_user(token))

    def test_valid_reset_token(self):
        u = User(password='dog')
        db.session.add(u)
        db.session.commit()
        token = u.generate_reset_token()
        self.assertTrue(User.reset_password(token, 'cat'))
        self.assertTrue(u.verify_password('cat'))

    def test_invalid_reset_token(self):
        u = User(password='dog')
        db.session.add(u)
        db.session.commit()
        token = u.generate_reset_token()
        self.assertFalse(User.reset_password(token + 'a', 'cat'))
        self.assertTrue(u.verify_password('dog'))

    def test_valid_change_email_token(self):
        u = User(email='nakul@yopmail.com', password='dog')
        db.session.add(u)
        db.session.commit()
        token = u.generate_email_change_token('sharma@yopmail.com')
        self.assertTrue(u.change_email(token))
        self.assertTrue(u.email == 'sharma@yopmail.com')

    def test_invalid_change_email_token(self):
        u = User(email='nakul@yopmail.com', password='dog')
        u2 = User(email='donald@yopmail.com', password='cat')
        db.session.add_all([u, u2])
        db.session.commit()
        token = u.generate_email_change_token('sharma@yopmail.com')
        self.assertFalse(u2.change_email(token))
        self.assertTrue(u2.email == 'donald@yopmail.com')

    def test_duplicate_change_email_token(self):
        u = User(email='nakul@yopmail.com', password='dog')
        u2 = User(email='donald@yopmail.com', password='cat')
        db.session.add_all([u, u2])
        db.session.commit()
        token = u.generate_email_change_token('donald@yopmail.com')
        self.assertFalse(u.change_email(token))
        self.assertTrue(u.email == 'nakul@yopmail.com')

    def test_user_role(self):
        u = User(email='john@example.com', password='cat')
        self.assertTrue(u.can(Permission.FOLLOW))
        self.assertTrue(u.can(Permission.COMMENT))
        self.assertTrue(u.can(Permission.WRITE))
        self.assertFalse(u.can(Permission.MODERATE))
        self.assertFalse(u.can(Permission.ADMIN))

    def test_anonymous_user(self):
        u = AnonymousUser()
        self.assertFalse(u.can(Permission.FOLLOW))
        self.assertFalse(u.can(Permission.COMMENT))
        self.assertFalse(u.can(Permission.WRITE))
        self.assertFalse(u.can(Permission.MODERATE))
        self.assertFalse(u.can(Permission.ADMIN))

    def test_moderator_role(self):
        r = Role.query.filter_by(name='Moderator').first()
        u = User(email='john@example.com', password='cat', role=r)
        self.assertTrue(u.can(Permission.FOLLOW))
        self.assertTrue(u.can(Permission.COMMENT))
        self.assertTrue(u.can(Permission.WRITE))
        self.assertTrue(u.can(Permission.MODERATE))
        self.assertFalse(u.can(Permission.ADMIN))

    def test_admin_role(self):
        r = Role.query.filter_by(name='Administrator').first()
        u = User(email='john@example.com', password='cat', role=r)
        self.assertTrue(u.can(Permission.FOLLOW))
        self.assertTrue(u.can(Permission.COMMENT))
        self.assertTrue(u.can(Permission.WRITE))
        self.assertTrue(u.can(Permission.MODERATE))
        self.assertTrue(u.can(Permission.ADMIN))

    def test_timestamps(self):
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        self.assertTrue((datetime.utcnow() - u.member_since).total_seconds() < 3)
        self.assertTrue((datetime.utcnow() - u.last_seen).total_seconds() < 3)

    def test_ping(self):
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        time.sleep(2)
        last_seen_before = u.last_seen
        u.ping()
        self.assertTrue(u.last_seen > last_seen_before)

    def test_follow(self):
        u1 = User(password='cat')
        u2 = User(password='dog')
        self.assertTrue(u1.is_following(u1))
        self.assertTrue(u2.is_following(u2))
        self.assertFalse(u1.is_following(u2))
        self.assertFalse(u2.is_following(u1))
        timestamp_before = datetime.utcnow()
        u1.follow(u2)
        db.session.commit()
        timestamp_after = datetime.utcnow()
        self.assertTrue(u1.is_following(u2))
        self.assertTrue(u2.is_followed_by(u1))
        self.assertFalse(u2.is_following(u1))
        self.assertTrue(u1.followers.count() == 1)
        self.assertTrue(u2.followers.count() == 2)
        f = u2.followers.all()[-1]
        self.assertTrue(timestamp_before <= f.timestamp <= timestamp_after)
        u1.unfollow(u2)
        db.session.commit()
        self.assertTrue(u2.followers.count() == 1)
        self.assertFalse(u2.is_followed_by(u1))
        self.assertTrue(Follow.query.count() == 2)
        u1.follow(u2)
        db.session.commit()
        db.session.delete(u2)
        db.session.commit()
        self.assertTrue(Follow.query.count() == 1)

    def test_to_json(self):
        u = User(email='john@example.com', password='cat')
        db.session.add(u)
        db.session.commit()
        with self.app.test_request_context('/'):
            json_user = u.to_json()
            expected_keys = ['url', 'username', 'member_since', 'last_seen',
                             'posts_url', 'followed_posts_url', 'post_count']
            self.assertEqual(sorted(json_user.keys()), sorted(expected_keys))
            self.assertEqual('/api/v1/users/' + str(u.id), json_user['url'])
