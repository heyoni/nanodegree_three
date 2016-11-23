from handlers.basehandler import BaseHandler


class Logout(BaseHandler):
    def get(self):
        self.set_secure_cookie('user_id', '""; Path=/')
        # self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/blog/signup')