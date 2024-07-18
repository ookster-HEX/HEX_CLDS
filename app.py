from flask import Flask, render_template, flash, redirect, session, request, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, FileField
from wtforms.validators import DataRequired, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_bootstrap import Bootstrap
#from flask_mail import Mail, Message

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
basedir = os.path.abspath(os.path.dirname(__file__))

UPLOAD_FOLDER = "static"
ALLOWED_EXTENSIONS = set(["png", "jpg", "jpeg", "gif"])
app = Flask(__name__)
app.config['SECRET_KEY'] = 'OOK12345'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 8025

bootstrap = Bootstrap(app)
#mail = Mail(app)


#Database stuff - Don't change-----------------------------------------
#======================================================================
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
    'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    admin = db.Column(db.Boolean)
    blocked = db.Column(db.Boolean)
    forename = db.Column(db.String(128))
    surname = db.Column(db.String(128))

    def __repr__(self):
        return '<User {}>'.format(self.username) 

class Wand(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True, unique=True)
    wood = db.Column(db.String(128))
    available = db.Column(db.Boolean)
    core = db.Column(db.String(128))
    length = db.Column(db.Integer())
    cost = db.Column(db.Integer())
    img = db.Column(db.String(128))
    thumbnail = db.Column(db.String(128))

    def __repr__(self):
        return '<User {}>'.format(self.username) 

#END of database stuff-----------------------------------------------
#====================================================================

def addUser(username,password,admin,forename,surname):
    u = User.query.filter_by(username=username).first()
    if u:
        u.username=username
        u.password_hash=generate_password_hash(password)
        u.admin=admin
        u.blocked=False
        u.forename=forename
        u.surname=surname
    else:
        u = User(username=username,password_hash=generate_password_hash(password),admin=admin,forename=forename,surname=surname)
        db.session.add(u)
    db.session.commit()

def deleteUser(username):
    u = User.query.filter_by(username=username).first()
    if u:
        db.session.delete(u)
        db.session.commit()

def addWand(name,wood,available,core,length,cost,img,thumbnail):
    w = Wand.query.filter_by(name=name).first()
    if w:
        w.name=name
        w.wood=wood
        w.available=available
        w.core=core
        w.length=length
        w.cost=cost
        w.img=img
        w.thumbnail=thumbnail
    else:
        w = Wand(name=name,wood=wood,available=available,core=core,length=length,cost=cost,img=img,thumbnail=thumbnail)
        db.session.add(w)
    db.session.commit()

def deleteWand(name):
    w = Wand.query.filter_by(name=name).first()
    if w:
        db.session.delete(w)
        db.session.commit()

'''
addUser("bob","bob",False,"Test","Non-Admin")
addUser("andjack", "andy_one",True,"Andrew","Jack")
addUser("Tommy", "banana",True,"Thomas","Meredith")
addUser("grimjak", "cheese",False,"Graham","Jack")
addUser("test", "test",True,"Test","Admin")
addUser("EleJack12", "Orange124",True,"Elanor","Jack")

addWand("expensive","balsa",True,"Pidgeon feather",2,2000,"pointy.jpg","pointy.jpg")
addWand("curve handle","Elder",True,"thestral tail feather",15,25,"curvehandle.jpg","curvehandle.jpg")
addWand("very straight","Holly",True,"phoenix tail feather",11,30,"verystraight.jpg","verystraight.jpg")
addWand("straightish","Oak",True,"owl tail feather",12,20,"straightish.jpg","straightish.jpg")
'''

def send_mail(subject, sender, recipients, text_body, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    mail.send(msg)

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password',validators=[DataRequired()])
    submit = SubmitField('login')

class SignupForm(FlaskForm):
    forename = StringField('Forename', validators=[DataRequired()])
    surname = StringField('Surname', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password',validators=[DataRequired(),EqualTo('conpass', message = 'no match found. sorry')])
    conpass = PasswordField('confirm password', validators=[DataRequired()])    
    submit = SubmitField('Submit')

class AddWandForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    wood = StringField('Wood')
    available = BooleanField('Available')
    core = StringField('Core')
    length = IntegerField('Length')
    cost = IntegerField('Cost')
    image = FileField('image')
    submit = SubmitField('Submit')


@app.route("/")
@app.route("/index")
def home():
    return render_template('home.html')

@app.route("/wands")
def wands():
    return render_template('wands.html', wands = Wand.query.all(), numwands = len(Wand.query.all()))


@app.route("/about")
def about_us():
    return render_template('about_us.html')

@app.route("/login", methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = form.username.data
        dbuser = User.query.filter_by(username=user).first()
        print (dbuser)
        if dbuser:
            if dbuser.blocked:
                flash('sorry but the user '+user+' has been blocked from admin','danger')
                return redirect('/index')
            if check_password_hash(dbuser.password_hash,form.password.data):
                session['logged_in'] = True
                session['admin'] = dbuser.admin
                session['user'] = dbuser.id
                flash('Hello '+dbuser.forename+' welcome to olivewanders','success')
                return redirect('/index')
        flash('Invalid username or password','danger')
        return redirect('/login')
    return render_template('login.html', title='login', form = form)

@app.route("/signup", methods = ['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        user = form.username.data
        forename = form.forename.data
        surname = form.surname.data
        password = form.password.data
        addUser(user, password, False, forename, surname)
        flash('The user '+user+' has been signed up\nHi '+forename+' we hope you enjoy the website','success')
        return redirect('/login')
    return render_template('sign-up.html', title='login', form = form)

@app.route("/logout")
def logout():
    session['logged_in'] = False
    session['admin'] = False
    return redirect('/login')

@app.route("/admin1", methods = ['GET', 'POST'])
def admin1():
    form = AddWandForm()
    if form.validate_on_submit():
        print(form.name.data)
        f=form.image.data
        if f.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if allowed_file(f.filename):
            filename = secure_filename(f.filename)
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        addWand(form.name.data,form.wood.data,form.available.data,form.core.data,form.length.data,form.cost.data,filename,filename)
    return render_template('admin1.html', userlist = User.query.all(), form = form, wandlist = Wand.query.all())

@app.route("/block", methods=['GET','POST'])
def block():
    dbuser = User.query.filter_by(username=request.form.get('block')).first()
    if dbuser: 
        dbuser.blocked=True
        db.session.commit()
    return redirect('/admin1')

@app.route("/basket", methods=['GET','POST'])
def basket():   
    return render_template('basket.html')

@app.route("/unblock", methods=['GET','POST'])
def unblock():
    dbuser = User.query.filter_by(username=request.form.get('block')).first()
    if dbuser: 
        dbuser.blocked=False
        db.session.commit()
    return redirect('/admin1')

@app.route("/noadmin", methods=['GET','POST'])
def noadmin():
    dbuser = User.query.filter_by(username=request.form.get('noadmin')).first()
    if dbuser: 
        dbuser.admin=False
        db.session.commit()
    return redirect('/admin1')

@app.route("/makeadmin", methods=['GET','POST'])
def makeadmin():
    dbuser = User.query.filter_by(username=request.form.get('makeadmin')).first()
    if dbuser: 
        dbuser.admin=True
        db.session.commit()
    return redirect('/admin1')

@app.route("/nouse", methods=['GET','POST'])
def nouse():
    dbuser = User.query.filter_by(username=request.form.get('nouse')).first()
    if dbuser: 
        deleteUser(dbuser.username)
    return redirect('/admin1')

@app.route("/makeavail", methods=['GET','POST'])
def makeavail():
    dbwand = Wand.query.filter_by(name=request.form.get('makeavail')).first()
    if dbwand: 
        dbwand.available=True
        db.session.commit()
    return redirect('/admin1')

@app.route("/makeunavail", methods=['GET','POST'])
def makeunavail():
    dbwand = Wand.query.filter_by(name=request.form.get('makeunavail')).first()
    if dbwand: 
        dbwand.available=False
        db.session.commit()
    return redirect('/admin1')

@app.route("/nowand", methods=['GET','POST'])
def nowand():
    dbwand = Wand.query.filter_by(name=request.form.get('nowand')).first()
    if dbwand: 
        deleteWand(dbwand.name)
    return redirect('/admin1')

@app.route("/buywand", methods=['POST'])
def buywand():
    wand_id = request.form.get('buy').split(',')[0]
    user_id = request.form.get('buy').split(',')[1]
    print(wand_id,user_id)

    dbuser = User.query.filter_by(id=user_id).first()
    dbwand = Wand.query.filter_by(id=wand_id).first()

    print(dbuser.username,dbwand.name)
    return redirect('/wands')

@app.route("/testemail")
def testemail():
    send_mail('test 2','info@grimjak.org.uk', ['info@grimjak.org.uk'], 'test 2', 'test')
    return redirect('/index')

@app.route("/coud")
def coud():
    return render_template('admin-meet-countdoun.html')

if __name__ == '__main__':
    app.run(debug=True,port=8080,host='0.0.0.0')