from handlers.basehandler import BaseHandler
from models.upvotes import Upvote


class UpvotePost(BaseHandler):
    def get(self, post_id):
        uid = self.read_secure_cookie('user_id')
        if uid:
            upvote = Upvote.upvote(post_id, uid)
            if upvote:
                self.redirect('/blog/')
        else:
            self.render("signup-form.html")