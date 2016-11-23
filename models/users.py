from google.appengine.ext import db

from blog import make_pw_hash


class Accounts(db.Model):
    username = db.StringProperty(required=True)
    # stores hash|salt
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)

    @classmethod
    def createaccount(cls, user, pw, email=''):
        # checking to see if the account already exists. else we create it
        q = Accounts.all().filter('username =', user)
        if (q.get() and q.get().username != user) or not q.get():
            h_salt = make_pw_hash(user, pw)
            newaccount = Accounts(username=user, password=h_salt, email=email)
            newaccount.put()
            return newaccount