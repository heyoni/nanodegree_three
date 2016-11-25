import hashlib
import hmac
import os
import random
import re
import string

import jinja2
import webapp2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    """
    generic render function takes in a filename and returns one back with
    variables filled out
    """
    t = jinja_env.get_template(template)
    return t.render(params)


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


def blog_key(name='default'):
    """
    generating parent key for blog in Post
    """
    return db.Key.from_path('blogs', name)


# these two function hash the user's ID to prevent forging
from secret import secret


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return int(val)


# input validations
def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    pass_re = re.compile(r"^.{3,20}$")
    return password and pass_re.match(password)


def valid_email(email):
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return not email or EMAIL_RE.match(email)


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


# these two functions check that user/pw/salt exist or create them
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)


def valid_pw(name, pw, h):
    """Returns true if name/pw match database. Takes in password field from db."""
    salt = h.split('|')[0]
    new_hash = make_pw_hash(name, pw, salt)
    if new_hash == h:
        return True


def verify_uid(uid):
    """
    this method verifies that the uid actually exists in the database and returns True if so
    """
    try:
        acc = Accounts.get_by_id(int(uid))
    except:
        return False
    if acc:
        return acc


from models.post import Post
from models.users import Accounts
from handlers.basehandler import BaseHandler
from handlers.editcomments import EditComments
from handlers.editcomments import DeleteComment
from handlers.editpost import EditPost
from handlers.login import Login
from handlers.logout import Logout
from handlers.newpost import NewPost
from handlers.postpage import PostPage
from handlers.signup import Signup
from handlers.upvotepost import UpvotePost
from handlers.redirecthome import RedirectHome
from handlers.newcomment import NewComment


class BlogFront(BaseHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts=posts)


class Welcome(BaseHandler):
    def get(self):
        # if user is logged in, fetch 10 of users' posts
        uid = self.read_secure_cookie('user_id')
        if uid:
            acc = verify_uid(uid)
            if acc:
                posts = db.GqlQuery(
                    "SELECT * FROM Post WHERE user_id='%s' ORDER BY created "
                    "DESC LIMIT 10" % uid)
                # display welcome banner if user is just logging in
                if self.request.get('username'):
                    user = self.request.get('username')
                    self.render('welcome.html', posts=posts, username=user)
                else:
                    self.render('userpage.html', posts=posts)
            else:
                self.redirect('/blog/signup')
        else:
            self.redirect('/blog/signup')


app = webapp2.WSGIApplication([('/blog/signup', Signup),
                               ('/blog/welcome', Welcome),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/([0-9]+)/(delete)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog[/]?', BlogFront),
                               ('/blog/userhome', Welcome),
                               ('/blog/add_comment', NewComment),
                               ('/blog/([0-9]+)/(edit)', EditPost),
                               ('/blog/save/([0-9]+)', UpvotePost),
                               ('/blog/comment/([0-9]+)/(edit)', EditComments),
                               ('/blog/comment/([0-9]+)/(delete)', DeleteComment),
                               ('/.*?', RedirectHome),
                               ],
                              debug=True)
