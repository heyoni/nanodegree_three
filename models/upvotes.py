from google.appengine.ext import db

from blog import blog_key
from post import Post
from users import Accounts


class Upvote(db.Model):
    post_id = db.ReferenceProperty(Post, required=True)
    user = db.ReferenceProperty(Accounts, required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    # upvote post. if already upvoted, remove upvote
    @classmethod
    def upvote(cls, post_id, account_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        account = Accounts.get_by_id(int(account_id))
        upvote = Upvote.all().filter("user =", account.key()).filter(
            "post_id =", post.key()).get()
        if not upvote:
            if int(post.user_id.key().id()) != int(account.key().id()):
                upvote = Upvote(post_id=post.key(), user=account.key())
                upvote.put()
        else:
            upvote.delete()
