from blog import verify_uid, blog_key, check_secure_val
from handlers.basehandler import BaseHandler
from models.comments import Comments
from models.post import Post


class EditComments(BaseHandler):
    def post(self, comment_id, action=""):
        uid = self.request.cookies.get('user_id')
        user = verify_uid(uid.split('|')[0])
        postkey = self.request.get('parent_key')
        post = Post.get_by_id(int(postkey), parent=blog_key())
        comment = self.request.get('comment')

        if postkey and comment and check_secure_val(uid) and user:
            if action == "edit":
                orig_comment = Comments.get_by_id(int(comment_id))
                if orig_comment.user.key().id() == user.key().id():
                    orig_comment.comment = comment
                    orig_comment.put()
                    self.redirect('/blog/%s' % postkey)
            else:
                Comments.add_comment(post.key(), user.key(), comment)
                self.redirect('/blog/%s' % postkey)
        else:
            self.auth_render('welcome.html')

    def get(self, comment_id, action=""):
        self.redirect('/blog')


class DeleteComment(BaseHandler):
    def get(self, comment_id, method=""):
        uid = self.request.cookies.get('user_id')
        user = verify_uid(uid.split('|')[0])
        orig_comment = Comments.get_by_id(int(comment_id))
        if user:
            if orig_comment.user.key().id() == user.key().id():
                orig_comment.delete()
                self.redirect('/blog')
        else:
            self.auth_render('welcome.html')