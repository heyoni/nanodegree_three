from blog import verify_uid, blog_key, check_secure_val
from handlers.basehandler import BaseHandler
from models.comments import Comments
from models.post import Post


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