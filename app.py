from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from smtplib import SMTP
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import datetime
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from flask_gravatar import Gravatar


EMAIL = "dumy.aliulmg4@gmail.com"
PASSWORD = "dm06gheA1p)T*"

login_manager = LoginManager()
app = Flask(__name__)
login_manager.init_app(app)
app.secret_key = "what the hell?"
Bootstrap(app)
ckeditor = CKEditor(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blog-posts.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
gravatar = Gravatar(app, size=70, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)
db = SQLAlchemy(app=app)


class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True, unique=True)
    body = db.Column(db.String, nullable=False)
    image = db.Column(db.String, nullable=False)
    title = db.Column(db.String, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = db.Column(db.String, nullable=False)
    subtitle = db.Column(db.String, nullable=True)
    dates = db.Column(db.String, nullable=False)
    comments = db.relationship("Comments", backref="blogs", lazy=True)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, unique=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    posts = db.relationship("Blog", backref="user", lazy=True)
    comments = db.relationship("Comments", backref="comment_author", lazy=True)


class Comments(db.Model):
    id = db.Column(db.Integer, primary_key=True, unique=True)
    author = db.Column(db.String, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog.id"))
    text = db.Column(db.String, nullable=False)


db.create_all()


class Form(FlaskForm):
    title = StringField(label="Title", validators=[DataRequired()])
    subtitle = StringField(label="Subtitle", validators=[DataRequired()])
    image = StringField(label="img_url", validators=[DataRequired()])
    body = CKEditorField(label="body", validators=[DataRequired()])
    submit = SubmitField(label="Submit")


class RegisterForm(FlaskForm):
    name = StringField(label="Name", validators=[DataRequired()])
    email = StringField(label="Email", validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired(), Length(6)])
    submit = SubmitField(label="Register")


class LoginForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    submit = SubmitField(label="Login")


class CommentForm(FlaskForm):
    comment = CKEditorField(label="Comment", validators=[DataRequired()])
    submit = SubmitField(label="Submit Comment")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home_page():
    data = db.session.query(Blog).all()
    logedin = False
    user_id = 0
    if current_user.is_authenticated:
        logedin = True
        user_id = current_user.id
    return render_template('index.html', data=data, logedin=logedin, user_id=user_id)


@app.route('/contact', methods=["POST", "GET"])
def contact():
    logedin = False
    if current_user.is_authenticated:
        logedin = True
    if request.method == "POST":
        dat = request.form
        name = dat["name"]
        email = dat["email"]
        phone = dat["phone"]
        text = dat["text"]
        print(name, email, phone, text)
        with SMTP("smtp.gmail.com") as connect:
            connect.starttls()
            connect.login(user=EMAIL, password=PASSWORD)
            connect.sendmail(from_addr=EMAIL, to_addrs="aliulmg4@gmail.com",
                             msg=f"Subject:New massage!!\n\nName:{name}\n"
                             f"email: {email}\nphone: {phone}\n"
                             f"massage: {text}")
        return render_template('contact.html', massage=1, logedin=logedin)
    else:
        return render_template('contact.html', massage=2, logedin=logedin)


@app.route('/new-post', methods=["POST", "GET"])
@login_required
def new_post():
    logedin = False
    if current_user.is_authenticated:
        logedin = True
    form = Form()
    if request.method == "POST":
        if form.validate_on_submit():
            title = request.form.get("title")
            subtitle = request.form.get("subtitle")
            image = request.form.get("image")
            body = request.form.get("body")
            date = datetime.now()
            date = date.strftime(f"%B,%e,%Y")
            new = Blog(title=title, subtitle=subtitle, author=current_user.name, dates=date, body=body, image=image,
                       author_id=current_user.id)
            db.session.add(new)
            db.session.commit()
            return redirect(url_for("home_page"))
        else:
            return render_template('new-post.html', form=form, logedin=logedin)
    else:
        return render_template('new-post.html', form=form, logedin=logedin)


@app.route("/edit-post", methods=["POST", "GET"])
@login_required
def edit():
    logedin = False
    if current_user.is_authenticated:
        logedin = True
    if request.method == "GET":
        p_id = request.args.get("p_id")
        blog = db.session.query(Blog).get(p_id)
        form = Form(
            title=blog.title,
            subtitle=blog.subtitle,
            image=blog.image,
            body=blog.body
        )
        return render_template("new-post.html", form=form, ed=True, logedin=logedin)
    if request.method == "POST":
        form = Form()
        if form.validate_on_submit():
            p_id = request.args.get("p_id")
            update = db.session.query(Blog).get(p_id)
            update.title = request.form.get("title")
            update.subtitle = request.form.get("subtitle")
            update.image = request.form.get("image")
            update.body = request.form.get("body")
            db.session.commit()
            return redirect(url_for("home_page"))
        else:
            return render_template("new-post.html", form=form, ed=True, logedin=logedin)


@app.route("/delete")
@login_required
def delete():
    p_id = request.args.get("p_id")
    blog = db.session.query(Blog).get(p_id)
    db.session.delete(blog)
    db.session.commit()
    return redirect(url_for("home_page"))


@app.route('/article/<int:a_id>', methods=["POST", "GET"])
def post_page(a_id):
    form = CommentForm()
    logedin = False
    user_id = 0
    if current_user.is_authenticated:
        logedin = True
        user_id = current_user.id
    data = db.session.query(Blog).all()
    if request.method == "GET":
        for blogs in data:
            if int(a_id) == int(blogs.id):
                print(blogs.author_id)
                return render_template("post.html", blog=blogs, logedin=logedin, user_id=user_id, form=form)
    else:
        if form.validate_on_submit():
            comment = request.form.get("comment")
            new_comment = Comments(author_id=current_user.id, post_id=a_id, text=comment, author=current_user.name)
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("post_page", a_id=a_id))
        else:
            for blogs in data:
                if int(a_id) == int(blogs.id):
                    return render_template("post.html", blog=blogs, logedin=logedin, user_id=user_id, form=form)


@app.route("/register", methods=["POST", "GET"])
def register():
    logedin = False
    if current_user.is_authenticated:
        logedin = True
    form = RegisterForm()
    if request.method == "GET":
        return render_template("register.html", form=form)
    else:
        if form.validate_on_submit():
            name = request.form.get("name")
            email = request.form.get("email")
            password = request.form.get("password")
            hash_pass = generate_password_hash(password=password, method="pbkdf2:sha256", salt_length=8)
            if db.session.query(User).filter_by(email=email).first():
                flash("You've already registered with this emil.")
                return redirect(url_for("login"))
            else:
                new_user = User(name=name, email=email, password=hash_pass)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect(url_for("home_page"))
        else:
            return render_template("register.html", form=form)


@app.route("/login", methods=["POST", "GET"])
def login():
    form = LoginForm()
    if request.method == "GET":
        return render_template("login.html", form=form)
    else:
        if form.validate_on_submit():
            email = request.form.get("email")
            password = request.form.get("password")
            is_registered = db.session.query(User).filter_by(email=email).first()
            if is_registered is not None:
                if check_password_hash(pwhash=is_registered.password, password=password):
                    login_user(is_registered)
                    print(current_user.id)
                    return redirect(url_for("home_page"))
                else:
                    flash("Incorrect password.")
                    return render_template("login.html", form=form)
            else:
                flash("You're not Registered")
                return redirect(url_for("register"))
        else:
            return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home_page"))


if __name__ == '__main__':
    app.run(debug=True)
