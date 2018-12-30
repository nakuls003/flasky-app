from selenium import webdriver
import unittest, threading, re, time
from app import create_app, db
from app.models import Role, User
from app.fake import gen_posts, gen_users


class SeleniumTestCase(unittest.TestCase):
    client = None

    @classmethod
    def setUpClass(cls):
        options = webdriver.ChromeOptions()
        options.add_argument('headless')

        try:
            cls.client = webdriver.Chrome(chrome_options=options)
        except:
            pass
        if cls.client:
            cls.app = create_app('testing')
            cls.app_context = cls.app.app_context()
            cls.app_context.push()
            db.create_all()
            Role.insert_roles()

            import logging
            logger = logging.getLogger('werkzeug')
            logger.setLevel('ERROR')

            gen_users(10)
            gen_posts(10)

            admin_role = Role.query.filter_by(name='Administrator').first()
            u = User(email='john@example.com', username='john', password='cat', confirmed=True, role=admin_role)
            db.session.add(u)
            db.session.commit()

            cls.server_thread = threading.Thread(target=cls.app.run, kwargs={'debug': False})
            cls.server_thread.start()

            time.sleep(2)


    @classmethod
    def tearDownClass(cls):
        if cls.client:
            cls.client.get('http://localhost:5000/shutdown')
            cls.client.quit()
            cls.server_thread.join()
            db.session.remove()
            db.drop_all()
            cls.app_context.pop()

    def setUp(self):
        if not self.client:
            self.skipTest('Web browser not available')

    def tearDown(self):
        pass

    def test_admin_home_page(self):
        self.client.get('http://localhost:5000/')
        self.assertTrue(re.search('Hello,\s+Stranger!', self.client.page_source))

        self.client.find_element_by_link_text('Log In').click()
        self.client.implicitly_wait(30)
        self.assertIn('<h1>Login</h1>', self.client.page_source)

        self.client.find_element_by_name('email').send_keys('john@example.com')
        self.client.find_element_by_name('password').send_keys('cat')
        self.client.find_element_by_name('submit').click()
        self.client.implicitly_wait(30)
        self.assertTrue(re.search('Hello,\s+john!', self.client.page_source))

        self.client.find_element_by_link_text('Profile').click()
        self.client.implicitly_wait(30)
        self.assertIn('<h1>John</h1>', self.client.page_source)
