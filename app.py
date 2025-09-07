from flask import Flask, render_template, request, url_for, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import os
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit



# APP INITIALIZATION

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config['SECRET_KEY'] = 'ChatterAppFlaskProjectSiege'

db = SQLAlchemy(app)

migrate = Migrate(app, db)

bcrypt = Bcrypt(app)

socketio = SocketIO()

socketio.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# MODELS

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False, unique=True)
    password = db.Column(db.String(64), nullable=False)
    pfp = db.Column(db.String(200), default='static/uploads/default.png')
    posts = db.relationship('Posts', backref='author', lazy=True, cascade="all, delete-orphan")

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

class Messages(db.Model):
    mid = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(64), nullable=False)
    content = db.Column(db.Text, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

# SOCKETS

@socketio.on('connect')
def handle_connect():
    print('Connected Socket')

@socketio.on('user_join')
def handle_user_join(username):
    print(f"User {username} Joined!")

@socketio.on('new_message')
def handle_new_message(message):
    print(f'New Message: {message}')
    emit('chat', {"message": message}, broadcast=True)

# ROUTES

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = Users.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Successfully Logged In', 'success')
            return redirect(url_for('home'))
        else:
            flash('Incorrect Credentials', 'fail')
            return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'GET':
        return render_template('signup.html')

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try: 
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = Users(username=username, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Account Created Successfully, Please Login', 'success')
            return redirect(url_for('login'))
        except exc.SQLAlchemyError:
            flash('Username Already Taken', 'fail')
            return redirect(url_for('signup'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You Have Been Logged Out', 'success')
    return redirect(url_for('home'))

@app.route('/delete')
@login_required
def delete():
    db.session.delete(current_user)
    db.session.commit()
    flash('Account Deleted Successfully', 'success')
    return redirect(url_for('home'))

@app.route('/chats')
@login_required
def chats():
    return render_template('chats.html')

@app.route('/feed')
@login_required
def feed():
    posts = Posts.query.all()
    return render_template('feed.html', posts=posts)

@app.route('/newpost', methods=['GET', 'POST'])
def newpost():
    if request.method == 'GET': 
        return render_template('newpost.html')
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('postcontent')

        post = Posts(title=title, content=content, author=current_user)

        db.session.add(post)
        db.session.commit()
        flash('Post Created Successfully', 'success')
        return redirect(url_for('feed'))

@app.route('/post/delete/<int:post_id>')
def deletepost(post_id):
    post = Posts.query.get_or_404(post_id)
    if current_user.id == post.author.id:
        db.session.delete(post)
        db.session.commit()
        return redirect(url_for('feed'))

@app.route('/user', methods=['GET', 'POST'])
def user():
    if request.method == 'GET':
        return render_template('user.html')
    if request.method == 'POST':
        newusername = request.form.get('newuser')
        newuserpass = request.form.get('userpass')

        newpass = request.form.get('newpass')
        oldpass = request.form.get('oldpass')

        newpfp = request.files.get('pfpupload')

        password = request.form.get('password')
        repassword = request.form.get('repassword')

        user = Users.query.get(current_user.id)

        if newusername and newuserpass:
            if bcrypt.check_password_hash(user.password, newuserpass):
                user.username = newusername
            else:
                flash('Incorrect Password', 'fail')
                return redirect(url_for('user'))

        if oldpass and newpass:
            if not bcrypt.check_password_hash(user.password, oldpass):
                flash('Old Password Is Incorrect', 'fail')
                return redirect(url_for('user'))

            if oldpass == newpass:
                flash('Old Password Cannot Be The Same As New Password', 'fail')
                return redirect(url_for('user'))

            new_hashed_pass = bcrypt.generate_password_hash(newpass).decode('utf-8')
            user.password = new_hashed_pass

        if newpfp and newpfp.filename != '':
            filename = secure_filename(newpfp.filename)
            filepath = os.path.join('static/uploads', filename)
            newpfp.save(filepath)
            user.pfp = filepath

        if password and repassword:
            if password == repassword:
                if bcrypt.check_password_hash(user.password, password):
                    return redirect(url_for('delete'))
            if password != repassword:
                flash("Password And Confirm Password Don't Match", 'fail')
                return redirect(url_for('user'))
            else:
                flash("Incorrect Password", 'fail')
                return redirect(url_for('user'))

        db.session.commit()
        flash("Profile Updated Successfully", 'success')
        return redirect(url_for('user'))

# RUN

if __name__ == '__main__':
    socketio.run(app, debug=True)