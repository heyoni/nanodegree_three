from blog import verify_uid, blog_key
from handlers.basehandler import BaseHandler
from models.post import Post


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
            p = Post(parent=blog_key(), subject=subject, content=content,
                     user_id=uid)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)