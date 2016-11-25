from blog import BaseHandler
from models.post import Post
from blog import blog_key
from blog import verify_uid
from blog import check_secure_val
from models.comments import Comments


class NewComment(BaseHandler):
    def post(self):
        uid = self.request.cookies.get('user_id')
        user = verify_uid(uid.split('|')[0])
        postkey = self.request.get('parent_key')
        post = Post.get_by_id(int(postkey), parent=blog_key())
        comment = self.request.get('comment')
        if postkey and comment and check_secure_val(uid) and user:
            Comments.add_comment(post.key(), user.key(), comment)
            self.redirect('/blog/%s' % postkey)
        else:
            self.auth_render('login.html')
