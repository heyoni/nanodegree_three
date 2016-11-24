from google.appengine.ext import db

from blog import blog_key, check_secure_val
from handlers.basehandler import BaseHandler


class PostPage(BaseHandler):
    def get(self, post_id, modify=""):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        uid = self.read_secure_cookie('user_id')

        if not post:
            # self.error(404)
            return self.render("404.html")
            # return self.write('post not found.')
        # check if user has the right to delete
        if modify == "delete" and post:
            if int(post.user_id.key().id()) == uid:
                user_id = check_secure_val(self.request.cookies.get('user_id'))
                if user_id == int(post.user_id.key().id()):
                    post.delete()
                    self.render("welcome.html")
            else:
                self.auth_render("welcome.html")
        else:
            posts = [post, ]
            self.render("front.html", posts=posts)
