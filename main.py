from datetime import date
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, LoginForm, RegisterForm, CommentForm
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# Initialize SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.unauthorized_handler
def unauthorized():
    flash("You must be logged in to access this page.", "warning")
    return redirect(url_for('login'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = db.relationship('BlogPost', back_populates='author')
    comments = db.relationship('Comments', back_populates='user')


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    author = db.relationship('User', back_populates='posts')
    comments = db.relationship('Comments', back_populates='post', cascade="all, delete-orphan")


class Comments(UserMixin, db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(1000))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', back_populates='comments')
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'), nullable=False)
    post = db.relationship('BlogPost', back_populates='comments')


with app.app_context():
    db.create_all()


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():  # Checks if the form submission is valid
        name = form.name.data
        email = form.email.data
        password = form.password.data
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email is already registered. Please log in.', 'warning')
            return redirect(url_for('login'))

        new_user = User(email=email, name=name, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        except Exception as e:
            db.session.rollback()  # Rollback in case of error
            flash(f'Error adding user: {str(e)}', 'danger')
    else:
        print("Form did not validate.")  # Debug print
        print(form.errors)  # Print form errors for debugging

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('get_all_posts'))
            else:
                flash('Login Unsuccessful. Please check your password and try again.', 'danger')
        else:
            flash('Login Unsuccessful. This email is not registered.', 'danger')
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    is_admin = False
    if current_user.is_authenticated:
        if current_user.id == 1:
            is_admin = True
    return render_template("index.html", all_posts=posts, admin=is_admin)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    result = db.session.execute(db.select(Comments))
    comments = result.scalars().all()
    comments = [comment for comment in comments if comment.post_id == post_id]
    return render_template("post.html", post=requested_post, form=form, comments=comments)


@app.route('/post/<int:post_id>/add_comment', methods=['POST'])
@login_required
def add_comment(post_id):
    form = CommentForm()
    if form.validate_on_submit():
        new_comment = Comments(
            text=form.body.data,
            user_id=current_user.id,
            post_id=post_id
        )
        db.session.add(new_comment)
        try:
            db.session.commit()
            flash('Comment added successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding comment: {str(e)}', 'danger')
        return redirect(url_for('show_post', post_id=post_id))
    return redirect(url_for('show_post', post_id=post_id))


@app.route("/new-post", methods=["GET", "POST"])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False)
