from handlers.basehandler import BaseHandler


class Login(BaseHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        user = self.request.get('username')
        password = self.request.get('password')
        if self.verify_login(user, password):
            self.redirect('/blog/welcome?username=' + user)
        else:
            self.render('login.html',
                        invalid_login="Invalid username or password.")