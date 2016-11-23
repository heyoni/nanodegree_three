from google.appengine.ext import db
import sys
print(sys.path)

from blog import render_str
from post import Post
from users import Accounts


class Comments(db.Model):
    post_id = db.ReferenceProperty(Post, required=True)
    user = db.ReferenceProperty(Accounts, required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.comment.replace('\n', '<br>')
        return render_str("comment.html", c=self)

    @classmethod
    def add_comment(cls, postkey, user, comment):
        comment = Comments(post_id=postkey, user=user, comment=comment)
        comment.put()