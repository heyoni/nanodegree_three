from blog import valid_username, valid_password, valid_email
from handlers.basehandler import BaseHandler
from models.users import Accounts


class Signup(BaseHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username,
                      email=email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True
        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True
        # submit params if error is found
        if have_error:
            self.render('signup-form.html', **params)
        else:
            acc = Accounts.createaccount(username, password, email)
            if not acc:
                params['error_nametaken'] = "Username already exists."
                self.render('signup-form.html', **params)
            else:
                self.logout()
                self.set_secure_cookie('user_id', str(acc.key().id()))
                self.redirect('/blog/welcome?username=' + acc.username)