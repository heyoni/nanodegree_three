from google.appengine.ext import db

from blog import blog_key, verify_uid
from handlers.basehandler import BaseHandler
from models.post import Post


class EditPost(BaseHandler):
    def get(self, post_id, modify=""):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        self.render("newpost.html", subject=post.subject, content=post.content,
                    post_id=post.key().id())

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
                self.render("newpost.html", subject=post.subject,
                            content=post.content, post_id=post.key().id())
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)