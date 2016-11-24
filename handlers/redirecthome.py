from handlers.basehandler import BaseHandler


class RedirectHome(BaseHandler):
    def get(self):
        self.redirect('/blog')
