import os
import re

import hashlib

import webapp2
import jinja2
import random
import string
import hmac
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# generic render function takes in a filename and returns one back with variables filled out
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# generating parent blog for Post
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_id = db.StringProperty(required=True)

    # returns post.html with variables filled out
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class accounts(db.Model):
    username = db.StringProperty(required=True)
    # stores hash|salt
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)

    @classmethod
    def createaccount(cls, user, pw, email=''):
        # checking to see if the account already exists. else we create it
        q = accounts.all().filter('username =', user)
        if (q.get() and q.get().username != user) or not q.get():
            h_salt = make_pw_hash(user, pw)
            newaccount = accounts(username=user, password=h_salt, email=email)
            newaccount.put()
            return newaccount


class Comments(db.Model):
    post_id = db.ReferenceProperty(Post, required=True)
    user = db.ReferenceProperty(accounts, required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.comment.replace('\n', '<br>')
        return render_str("comment.html", c=self)

    @classmethod
    def add_comment(cls, postkey, user, comment):
        comment = Comments(post_id=postkey, user=user, comment=comment)
        comment.put()


class Upvote(db.Model):
    post_id = db.ReferenceProperty(Post, required=True)
    user = db.ReferenceProperty(accounts, required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    # upvote post. if already upvoted, remove upvote
    @classmethod
    def upvote(cls, post_id, account_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        account = accounts.get_by_id(int(account_id))
        upvote = Upvote.all().filter("user =", account.key()).filter("post_id =", post.key()).get()
        if not upvote:
            if post.user_id != account.key().id():
                upvote = Upvote(post_id=post.key(), user=account.key())
                upvote.put()
            else:
                return False
        else:
            upvote.delete()


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
        acc = accounts.all().filter('username', user)
        if acc.get():
            pwvalid = valid_pw(user, password, acc.get().password)
            if pwvalid:
                self.set_secure_cookie('user_id', str(acc.get().key().id()))
                return True

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


class BlogFront(BaseHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts=posts)


class PostPage(BaseHandler):
    def get(self, post_id, modify=""):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        uid = self.read_secure_cookie('user_id')

        if not post:
            # self.error(404)
            return self.write('post not found.')
        # check if user has the right to delete
        if modify == "delete" and post and post.user_id == uid:
            user_id = check_secure_val(self.request.cookies.get('user_id'))
            if user_id == post.user_id:
                post.delete()
            self.render("welcome.html")
        else:
            posts = [post, ]
            self.render("front.html", posts=posts)


class EditPost(BaseHandler):
    def get(self, post_id, modify=""):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        self.render("newpost.html", subject=post.subject, content=post.content, post_id=post.key().id())

    def post(self, post_id, modify=""):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        uid = self.read_secure_cookie('user_id')
        post_id = self.request.get('post_id')
        subject = self.request.get('subject')
        content = self.request.get('content')
        # if user is authorized
        if modify == "edit" and post and post.user_id == uid:
            # if the post exists and the forms/cookies are valid, update post
            if post_id and (subject and content) and uid and verify_uid(uid):
                post = Post.get_by_id(int(post_id), parent=blog_key())
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/blog/%s' % post_id)
            else:
                # if any text is missing, send back to post editing page
                self.render("newpost.html", subject=post.subject, content=post.content, post_id=post.key().id())
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


class UpvotePost(BaseHandler):
    def get(self, post_id):
        uid = self.read_secure_cookie('user_id')
        if uid:
            upvote = Upvote.upvote(post_id, uid)
            if upvote:
                self.redirect('/blog/')
        else:
            self.render("signup-form.html")


class NewPost(BaseHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        uid = self.read_secure_cookie('user_id')
        post_id = self.request.get('post_id')
        # check that all the forms/uid are valid
        if (subject and content) and uid and verify_uid(uid):
            # when editing, post_id will exist
            if post_id:
                post = Post.get_by_id(post_id)
                post(parent=blog_key(), subject=subject, content=content)
                post.put()
            p = Post(parent=blog_key(), subject=subject, content=content, user_id=uid)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


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
            acc = accounts.createaccount(username, password, email)
            if not acc:
                params['error_nametaken'] = "Username already exists."
                self.render('signup-form.html', **params)
            else:
                self.logout()
                self.set_secure_cookie('user_id', str(acc.key().id()))
                self.redirect('/blog/welcome?username=' + acc.username)


class Welcome(BaseHandler):
    def get(self):
        # if user is logged in, fetch 10 of users' posts
        uid = self.read_secure_cookie('user_id')
        if uid:
            acc = verify_uid(uid)
            if acc:
                posts = db.GqlQuery("SELECT * FROM Post WHERE user_id='%s' ORDER BY created DESC LIMIT 10" % uid)
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


class Login(BaseHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        user = self.request.get('username')
        password = self.request.get('password')
        if self.verify_login(user, password):
            self.redirect('/blog/welcome?username=' + user)
        else:
            self.render('login.html', invalid_login="Invalid username or password.")


class Logout(BaseHandler):
    def get(self):
        self.set_secure_cookie('user_id', '""; Path=/')
        # self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/blog/signup')


class EditComments(BaseHandler):
    def post(self):
        uid = self.request.cookies.get('user_id')
        user = verify_uid(uid.split('|')[0])
        postkey = self.request.get('parent_key')
        post = Post.get_by_id(int(postkey), parent=blog_key())
        comment = self.request.get('comment')

        if postkey and comment and check_secure_val(uid) and user:
            Comments.add_comment(post.key(), user.key(), comment)
            self.redirect('/blog/%s' % postkey)


class Rot13(BaseHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text=rot13)


# these two function hash the user's ID to prevent forging
from secret import secret


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# input validations
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


# these two functions check that user/pw/salt exist or create them
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)


# Returns true if name/pw match database. Takes in password field from db.
def valid_pw(name, pw, h):
    salt = h.split('|')[0]
    new_hash = make_pw_hash(name, pw, salt)
    if new_hash == h:
        return True


def verify_uid(uid):
    acc = accounts.get_by_id(int(uid))
    if acc:
        return acc


app = webapp2.WSGIApplication([('/rot13', Rot13),
                               ('/blog/signup', Signup),
                               ('/blog/welcome', Welcome),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/([0-9]+)/(delete)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog[/]?', BlogFront),
                               ('/blog/userhome', Welcome),
                               ('/blog/add_comment', EditComments),
                               ('/blog/([0-9]+)/(edit)', EditPost),
                               ('/blog/save/([0-9]+)', UpvotePost),
                               ],
                              debug=True)
