import os
import re
import random
import hashlib
import hmac
import time
import webapp2
import jinja2

from string import letters

from google.appengine.ext import db

# template directory code to for template files
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'mkcldcdsmciosdjcmdfiovdfkavmfvkaomwev'

# Global function for rendering a string which does not inherit from the class Handler
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# functions for hashing and validating password hashing
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    # split at the pipe and compare to make sure value is valid
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# convenience code to make write easier to use (so we can use self.write)
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        # secures the val and stores the info in the cookie
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        # finds cookie and if it exists and checks if it is secure then it returns the cookie_val
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        # sets the cookie for the login
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        # checks to see if user is logged in or not
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, p):
    response.out.write('<b>' + p.subject + '</b><br>')
    response.out.write(p.content)

# User Information
def make_salt(length = 5):
    # makes a string of five letters
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    # make a password hash
    if not salt:
        salt = make_salt()
    # hash the password in 256
    h = hashlib.sha256(name + pw + salt).hexdigest()
    # returns the salt and hashed password
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    # verify the password
    salt = h.split(',')[0]
    # make sure the hash in database matches the new one
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    # creates the database to store the users
    return db.Key.from_path('users', group)

class User(db.Model):
    # user object that stores in the database
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    # call this to get the user of the user out of the database
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    # looks up user by name and returns it
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    # takes name, password and email and creates a new user object
    def register(cls, name, pw, email = None):
        # create password hash
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    # creates login by name
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# Blog
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# Blog Post Parameters
class Post(db.Model):
    author = db.StringProperty()
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    likes = db.IntegerProperty()
    likes_users = db.StringListProperty()
    last_modified = db.DateTimeProperty(auto_now = True)

    # render blog entry as HTML
    def render(self):
        # Adds a line break for user that enters in text on new line
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)


# Handler for getting and adding new Post
class NewPost(BlogHandler):
    # Get the post
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            error = "Please log in to write a new post!"
            self.redirect("/login", error=error)

    # Posting new post
    def post(self):
        if not self.user:
            error = "Please log in to write a new post!"
            return self.redirect("/login", error=error)

        # Get the author, subject and content
        author = self.user.name
        content = self.request.get('content')
        likes = 0
        subject = self.request.get('subject')
        

        # if there is a subject and content create a new post and add to the blog and return the post
        if subject and content:
            # Set parent to blog_key() for future organization purposes
            p = Post(parent = blog_key(), subject = subject, content = content, author = author, likes = likes)
            # stores the element in the database
            p.put()
            # redirects user to the blog post with the id of the element
            self.redirect('/blog/%s' % str(p.key().id()))
        # if subject and content not there, error message appears
        else:
            error = "You need to fill in both a subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

# Handler for posting the page
class PostPage(BlogHandler):
    # create a key - Find a post with an id, whose parent is blog key
    def get(self, post_id):
        # key that finds the Post
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        
        # store the key in post
        p = db.get(key)

        # if no post return a 404
        if not p:
            self.error(404)
            return self.render("404.html")

        # if there is a post, return permalink with the post
        self.render("permalink.html", p = p)

# Handler for getting and editing a Post
class EditPost(BlogHandler):
    # create a key - Find a post with an id, whose parent is blog key
    def get(self, post_id):
        # key that finds the Post
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        # store the key in post
        p = db.get(key)

        # if no post return a 404
        if not p:
            self.error(404)
            return self.render("404.html")

        # if not logged in, go back to login
        if not self.user:
            error = "Please log in to write a new post!"
            return self.redirect("/login", error=error)

        # if the user = the author allow edit
        if self.user.name == p.author:
            self.render("editpost.html", p = p, subject = p.subject, content = p.content)
        else:
            error = "You must be logged in to edit your post!"
            return self.render("login-form.html", error = error)

    # Posting the edited post
    def post(self, post_id):
        # key that finds the Post
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        # store the key in post
        p = db.get(key)

        # check if post exists
        if not p:
            error = "This post doesn't exist. Please log in and try again."
            return self.redirect("login-form.html", error = error)

        # Get the author, subject and content
        content = self.request.get("content")
        subject = self.request.get("subject")
        
        # if the user is the same as the author and there is a subject and content create a new post and add to the blog and return the post
        if self.user.name == p.author:
            if subject and content:
                p.subject = subject
                p.content = content
                # stores the element in the database
                p.put()
                # redirects user to the blog post with the id of the element
                self.redirect('/blog/%s' % str(p.key().id()))
            # if subject and content not there, error message appears
            else:
                error = "You need to fill in both a subject and content, please!"
                self.render("edit.html", p=p, subject=subject, content=content, error=error)
        else:
            error = "You need to be logged in order to edit your post!"
            return self.render("login-form.html", error=error)

# Handler for getting and deleting a Post
class DeletePost(BlogHandler):
    def get(self, post_id):
        # key that finds the Post
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        # store the key in post
        p = db.get(key)

        # check if post exists
        if not p:
            error = "This post doesn't exist. Please log in and try again."
            return self.redirect("login-form.html", error = error)

        # if not logged in, go back to login
        if not self.user:
            error = "Please log in to write a new post!"
            return self.redirect("/login", error=error)

        if self.user.name == p.author:
            p.delete()
            message = "Your post has been deleted."
            self.render("front.html", p=p, message = message)
        else:
            error = "You may only delete your posts."
            return self.render("login-form.html", error=error)

# Comment Post Parameters
class Comment(db.Model):
    comment = db.TextProperty(required = True)
    commentAuthor = db.StringProperty(required = True)
    commentID = db.IntegerProperty(required = True)
    commentCreated = db.DateTimeProperty(auto_now_add = True)


# Handler for user to write a comment
class WriteComment(BlogHandler):
    # create a key - Find a post with an id, whose parent is blog key
    def get(self, post_id):
        # key that finds the Post
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        # store the key in post
        p = db.get(key)

        # check if post exists
        if not p:
            error = "This post doesn't exist. Please log in and try again."
            return self.redirect("login-form.html", error = error)

        # if logged in
        if self.user:
            self.render("comment.html", p = p, subject = p.subject, content = p.content)
        else:
            error = "You must be logged in to comment on a post!"
            return self.render("login-form.html", error = error)

    # Posting the comment on the post
    def post(self, post_id):
        # key that finds the Post
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        # store the key in post
        p = db.get(key)

        if not p:
            error = "This post doesn't exist. Please log in and try again."
            return self.redirect("login-form.html", error = error)

        # Get the author, subject and content
        commentOriginal = self.request.get("comment")
        comment = commentOriginal.replace('\n', '<br>')
        commentAuthor = self.user.name
        commentID = int(p.key().id())
        
        # if the user is logged in and there is an author and comment create a new comment and add to the blog and return the post
        if self.user:
            if comment and commentAuthor and commentID:
                c = Comment(parent = blog_key(), comment = comment, commentAuthor = commentAuthor, commentID = commentID)
                # stores the element in the database
                c.put()
                # redirects user to the blog post with the id of the element
                time.sleep(0.5)
                self.redirect('/blog')
            # if subject and content not there, error message appears
            else:
                error = "You need to enter in a comment!"
                self.render("comment.html", p=p, subject=p.subject, content=p.content, error=error)

# Handler for getting and editing a Comment
class EditComment(BlogHandler):
    # create a key - Find a comment with an id, whose parent is blog key
    def get(self, comment_id):
        # key that finds the Comment
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())

        # store the key in comment
        c = db.get(key)

        # if no post return a 404
        if not c:
            self.error(404)
            return self.render("404.html")

        # replacing the comment
        commentEdit = c.comment.replace('<br>', '')

        # if the user is logged in allow edit
        if self.user.name == c.commentAuthor:
            self.render("editcomment.html", c = c, commentEdit = commentEdit)
        else:
            error = "You must be logged in to edit the comment!"
            return self.render("login-form.html", error = error)

    # Posting the edited Comment
    def post(self, comment_id):
        # key that finds the Comment
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())

        # store the key in post
        c = db.get(key)

        if not c:
            error = "This comment doesn't exist. Please log in and try again."
            return self.redirect("login-form.html", error = error)

        # Get the author, subject and content
        commentOriginal = self.request.get("comment")
        comment = commentOriginal.replace('\n', '<br>')
        commentAuthor = c.commentAuthor
        commentID = c.commentID
        
        # if the user is logged in and there is an author and comment post the edited comment and add to the blog and return the post
        if self.user.name == c.commentAuthor:
            if comment and commentAuthor and commentID:
                c.comment = comment
                c.commentAuthor = commentAuthor
                # stores the element in the database
                c.put()
                # redirects user to the blog post with the id of the element
                time.sleep(0.5)
                self.redirect('/blog')
            # if subject and content not there, error message appears
            else:
                error = "You need to enter in a comment!"
                self.render("editcomment.html", c=c, commentEdit = c.comment)

# Handler for getting and deleting a Comment
class DeleteComment(BlogHandler):
    def get(self, comment_id):
        # key that finds the Comment
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())

        # store the key in comment
        c = db.get(key)
        
        if not c:
            error = "This comment doesn't exist. Please log in and try again."
            return self.redirect("login-form.html", error = error)

        # if not logged in, go back to login
        if not self.user:
            error = "Please log in to delete comment!"
            return self.redirect("/login", error=error)


        if self.user.name == c.commentAuthor:
            c.delete()
            message = "Your comment has been deleted."
            self.render("front.html", c = c, message = message)
        else:
            error = "You may only delete your posts."
            return self.render("login-form.html", error = error)

# Handler to create Likes for a post and updates how many likes
class UserLike(BlogHandler):
    def post(self, post_id):
        # key that finds the Post
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())

        # store the key in post
        p = db.get(key)

        if not p:
            error = "This post doesn't exist to like. Please log in and try again."
            return self.redirect("login-form.html", error = error)

        # add a like to the counter
        p.likes = p.likes + 1
        p.likes_users.append(self.user.name)

        # if the user is not the post author then put add the like
        if self.user.name != p.author:
            p.put()
            time.sleep(0.5)
            self.redirect("/blog")
        else:
            error="You cannot like your own posts!"
            return self.render("/blog", error = error)

# Checks to be sure the username, password and email are correct syntax on signup form
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
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

        params = dict(username = self.username,
                      email = self.email)

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
        raise NotImplementedError

class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            # stores the user in the database
            u.put()

            # set the cookie
            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            username = self.user.name
            self.render('welcome.html', username = username)
        else:
            self.redirect('/blog')

# Handler for /blog
class BlogFront(BlogHandler):
    def get(self):
        # look up all the posts and comments
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        comments = db.GqlQuery("SELECT * FROM Comment ORDER BY commentCreated DESC")
        # Renders the posts and comments in front.html using the posts variable
        self.render("front.html", posts = posts, comments = comments)

app = webapp2.WSGIApplication([('/', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage), # passing an integer parameter into PostPage Handler
                               ('/blog/login', Login),
                               ('/blog/newpost', NewPost),
                               ('/blog/signup', Register),
                               ('/blog/logout', Logout),
                               ('/blog/welcome,', Welcome),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/comment/([0-9]+)', WriteComment),
                               ('/blog/comment-edit/([0-9]+)', EditComment),
                               ('/blog/comment-delete/([0-9]+)', DeleteComment),
                               ('/blog/like/([0-9]+)', UserLike)
                            ],
                            debug=True)
