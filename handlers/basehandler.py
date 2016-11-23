import webapp2

from blog import verify_uid, render_str, make_secure_val, check_secure_val, valid_pw
from models.users import Accounts


class BaseHandler(webapp2.RequestHandler):
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and verify_uid(uid)

    def render(self, template, **kw):
        kw['user'] = self.user
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # reads the cookie from user's requests and sends back the ID alone
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # sets user_id cookie in headers if login/pw matches
    def verify_login(self, user, password):
        acc = Accounts.all().filter('username', user)
        if acc.get():
            pwvalid = valid_pw(user, password, acc.get().password)
            if pwvalid:
                self.set_secure_cookie('user_id', str(acc.get().key().id()))
                return True

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')