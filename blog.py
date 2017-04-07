import os
import re
import random
import hashlib
import hmac
from string import letters
import logging
import webapp2
import jinja2

from google.appengine.ext import db

# connect jinja to html template folder
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'fart'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    """
    create array of value and hash(value)
    :param val: value to be hashed
    :return: value and hash(value)
    """
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    """
    check if the value in secure value has not changed
    :param secure_val: value and hash(value)
    :return: value
    """
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    """
    Parent Class for all Website handler classes
    provide the main functions as write html and cookie process
    """

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


# blog stuff
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# database stuff
class User(db.Model):
    """
    User datastore model
    """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    """
    Post datastore model
    """
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    owner = db.StringProperty(required=True)
    likes = db.StringListProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class Comment(db.Model):
    """
    Comment datastore model
    """
    content = db.TextProperty(required=True)
    owner = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    post_reference = db.ReferenceProperty(Post)


class BlogFront(BlogHandler):
    """Display list of post"""

    def get(self):
        logging.info("BlogFront___________________")
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    """Display blog permalink page"""

    def get(self, post_id):
        error = self.request.get('error')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comments = Comment.all()
        comments.filter("post_reference =", post.key())
        c = comments.order("created")
        if not post:
            self.error(404)
            return
        self.render("permalink.html", post=post, c=c, error=error)

    def post(self, post_id):
        logging.info("Comment____________________")
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            content = self.request.get('content')
            owner = self.user.name
            if content:
                # Add comment to datastore
                c = Comment(content=content, owner=owner,
                            post_reference=post.key())
                c.put()
            self.redirect("/blog/%s" % post_id)
        else:
            # redirect to login page .. public user can not comment
            self.redirect("/login")


class EditComment(BlogHandler):

    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            if comment.owner == self.user.name:
                self.render("edit-comment.html", c=comment)
            else:
                # redirect to post page .. user can only edit his comment
                self.redirect(
                    "/blog/%s" % post_id +
                    "?error=You are not authorized to edit this comment")
        else:
            # redirect to login page .. public user can not edit comment
            self.redirect("/login")

    def post(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            content = self.request.get('content')
            if content:
                # update comment content
                comment.content = content
                comment.put()
            self.redirect("/blog/%s" % post_id)
        else:
            # redirect to login page .. public user can not edit comment
            self.redirect("/login")


class EditPost(BlogHandler):

    def get(self, post_id):
        if self.user:
            logging.info(
                "Test Edit___________________________________________")
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.owner == self.user.name:
                self.render("edit.html", post=post)
            else:
                # redirect to post page .. user can only edit his post
                self.redirect("/blog/%s" % post_id +
                              "?error=You are't authorized to edit this post")
        else:
            # redirect to login page .. public user can not edit posts
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        subject = self.request.get('subject')
        content = self.request.get('content')
        if self.user.name == post.owner:
            if subject and content:
                # update post
                post.subject = subject
                post.content = content
                post.put()
                self.redirect("/blog/%s" % str(post_id))
            else:
                # if user enter empty subject or content
                error = "subject and content, please!"
                self.render("edit.html", post=post, error=error)
        else:
            # redirect to login page .. public user can not edit comment
            self.render("edit.html", post=post,
                        error="You are not authorized to edit this post")


class DeleteComment(BlogHandler):
    """Display delete confirmation page"""

    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            if comment.owner == self.user.name:
                self.render("delete.html", post_id=post_id)
            else:
                # redirect to post page .. user can only delete his comments
                self.redirect("/blog/%s" % post_id +
                              "?error=You are't authorized to delete comment")
        else:
            # redirect to login page ..public user can not delete any comments
            self.redirect("/login")

    def post(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            if comment.owner == self.user.name:
                comment.delete()
                self.redirect("/blog/%s" % post_id)
            else:
                # redirect to post page .. user can only delete his comments
                self.redirect("/blog/%s" % post_id +
                              "?error=You are't authorized to delete comment")
        else:
            # redirect to login page ..public user can not delete any comments
            self.redirect("/login")


class DeletePost(BlogHandler):

    def get(self, post_id):
        if self.user:
            logging.info("user ___________________________________________")
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.owner == self.user.name:
                self.render("delete.html", post_id=post_id)
            else:
                # redirect to post page .. user can only delete his posts
                self.redirect("/blog/%s" % post_id +
                              "?error=You are't authorized to delete post")
        else:
            # redirect to login page ..public user can not delete any posts
            self.redirect("/login")

    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if self.user.name == post.owner:
                post.delete()
                self.redirect("/blog")
            else:
                # redirect to post page .. user can only delete his posts
                self.render("delete.html",
                            error="You are not authorized to delete this post")
        else:
            # redirect to login page ..public user can not delete any posts
            self.redirect("/login")


class LikePost(BlogHandler):

    def get(self, post_id):
        if self.user:
            logging.info("Like --------------------------------------------")
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            # user can not like his post
            if self.user.name == post.owner:
                self.redirect("/blog")
            # if user alerdey like post >> remove like
            elif self.user.name in post.likes:
                post.likes.remove(self.user.name)
                post.put()
                self.redirect("/blog/%s" % post_id)
            else:
                # add like
                post.likes.append(self.user.name)
                post.put()
                self.redirect("/blog/%s" % post_id)
        else:
            # public users can not like any post
            self.redirect("/login")


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            # public user  can not add post
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')
        subject = self.request.get('subject')
        content = self.request.get('content')
        owner = self.user.name
        if subject and content and owner:
            # create and add new post to datastore
            p = Post(parent=blog_key(), subject=subject,
                     content=content, owner=owner)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, owner=owner, error=error)


# regular expression to make sure that user name is 3 -20 char
# and user name is letters and/or numbers
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    """
    Test user name match rule of username regular expression or not
    :param username:
    :return: boolen true if match , else false
    """
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        self.render('welcome.html', username=self.user.name)


class Register(Signup):

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.render('welcome.html', username=self.username)


class Login(BlogHandler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.render('welcome.html', username=username)
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/signup')


app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/edit/([0-9]+)', EditPost),
                               ('/delete/([0-9]+)', DeletePost),
                               ('/like/([0-9]+)', LikePost),
                               ('/blog/([0-9]+)/editComment/([0-9]+)',
                                EditComment),
                               ('/blog/([0-9]+)/deleteComment/([0-9]+)',
                                DeleteComment),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
