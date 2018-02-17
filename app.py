from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

from flask import Flask
from flask_mail import Mail, Message

from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)


########### Configurations for email ###########################

##############make sure to add password################
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'amcp37@gmail.com'
app.config['MAIL_PASSWORD'] = '*******'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail=Mail(app)


########### Configurations for SQLAlchemy ###########################
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/myflaskapp'
db = SQLAlchemy(app)


########### Users Model ###########################
class Users(db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(100),nullable=False)
	email = db.Column(db.String(50),nullable=False)
	username = db.Column(db.String(30),nullable=False)
	password = db.Column(db.String(100),nullable=False)
	register_date = db.Column(db.TIMESTAMP,nullable=False)

	def __init__(self,name,email,username,password):
		self.name = name
		self.email = email
		self.username = username
		self.password = password


########### Articles Model ###########################
class Articles(db.Model):
	__tablename__ = 'articles'
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(255),nullable=True)
	author = db.Column(db.String(100), nullable=True)
	body = db.Column(db.Text, nullable=True)
	create_date = db.Column(db.TIMESTAMP, nullable=False)

	def __init__(self, title, author, body):
		self.title = title
		self.author = author
		self.body = body
		

########### Tasks Model ###########################
class Tasks(db.Model):
	__tablename__ = 'tasks'
	id = db.Column(db.Integer, primary_key=True)
	user = db.Column(db.String(15), nullable=False)
	task = db.Column(db.String(50), nullable=False)
	created_date = db.Column(db.TIMESTAMP, nullable=False)
	status = db.Column(db.Integer, nullable = True)

	def __init__(self, user, task, status):
		self.user = user
		self.task = task
		self.status = status

########### End Models ###########################
db.create_all()
db.session.commit()


########### Index Route ###########################
@app.route('/')
def index():
	return render_template('home.html')


########### About Route ###########################
@app.route('/about')
def about():
	return render_template('about.html')


########### Articles Route ###########################
@app.route('/articles')
def articles():

	articles = Articles.query.all()

	if(articles) :
		return render_template('articles.html', articles=articles)
	else:
		msg = 'No Articles Found'
		return render_template('articles.html', msg=msg)


########### Single Article Route ###########################
@app.route('/article/<string:id>/')
def article(id):

	article = Articles.query.get(id) 
	return render_template('article.html', article=article)

########### Register Form Class ###########################
class RegisetForm(Form):
	name = StringField('Name', [validators.Length(min=1, max=50)])
	username = StringField('Username', [validators.Length(min=4, max=25)])
	email = StringField('Email', [validators.Length(min=10, max=50)])
	password = PasswordField('Password', [
		validators.DataRequired(),
		validators.EqualTo('confirm', message='Passwords do not match')
	])

	confirm = PasswordField('Confirm Password')



########### User Registration Route ###########################
@app.route('/register', methods=['GET', 'POST'])
def register():
	form = RegisetForm(request.form)
	if request.method == 'POST' and form.validate():
		name = form.name.data
		email = form.email.data
		username = form.username.data
		#encrypt the password before sending
		password = sha256_crypt.encrypt(str(form.password.data))
		user = Users(name,email,username,password)
		db.session.add(user)
		db.session.commit()
		flash('You are now registered and can log in', 'success')
		return redirect(url_for('index'))
	return render_template('register.html', form=form)


########### User Login Route ###########################
@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		# Get form fields
		username = request.form['username']
		password_candidate = request.form['password']
		
		result = Users.query.filter_by(username = username).first()

		if (result):
			password = result.password
			# Compare the passwords
			if sha256_crypt.verify(password_candidate, password):
				# Passed
				session['logged_in'] = True
				session['username'] = username
				flash('You are now logged in', 'success')
				return redirect(url_for('dashboard'))

			else:
				error = 'Invalid Login'
				return render_template('login.html', error=error)	

		else:
			error = 'Username not found'
			return render_template('login.html', error=error)	

	return render_template('login.html')



########### Check if user logged in ###########################
def is_logged_in(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			return f(*args, ** kwargs)
		else:
			flash('Unauthorized, Please login', 'danger')
			return redirect(url_for('login'))
	return wrap
			

########### Logout Route ###########################
@app.route('/logout')
@is_logged_in
def logout():
	session.clear()
	flash('You are now logged out', 'success')
	return redirect(url_for('login'))


########### Dashboard Route ###########################
@app.route('/dashboard')
@is_logged_in
def dashboard():
	articles = Articles.query.all()

	if (articles):
		return render_template('dashboard.html', articles=articles)
	else:
		msg = 'No Articles Found'
		return render_template('dashboard.html', msg=msg)


########### Article form class #####################
class ArticleForm(Form):
	title = StringField('Title', [validators.Length(min=1, max=200)])
	body = TextAreaField('Body', [validators.Length(min=30)])

	
########### Add Article Route ###########################
@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
	form = ArticleForm(request.form)
	if request.method == 'POST' and form.validate():
		title = form.title.data
		body = form.body.data

		####### SQLAlchemy Queries #########
		article = Articles(title, session['username'], body)
		db.session.add(article)
		db.session.commit()

		flash('Article Created', 'success')
		return redirect(url_for('dashboard'))

	return render_template('add_article.html',form=form)


########### Edit Article Route ###########################
@app.route('/edit_article/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
	article = Articles.query.get(id)
	form = ArticleForm(request.form)
	form.title.data = article.title
	form.body.data = article.body

	if request.method == 'POST' and form.validate():

		article.title = request.form['title']
		article.body = request.form['body']
		db.session.commit()

		flash('Article Updated', 'success')
		return redirect(url_for('dashboard'))

	return render_template('edit_article.html',form=form)


########### Delete Article Route ###########################
@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
	article = Articles.query.get(id)
	db.session.delete(article)
	db.session.commit()
	flash('Article Deleted', 'success')
	return redirect(url_for('dashboard'))


########### To-Do List Route ###########################
@app.route('/to_do')
@is_logged_in
def to_do():
	tasks = Tasks.query.all()

	if (tasks):
		return render_template('to_do.html', tasks=tasks)
	else:
		msg = 'No Tasks Found'
		return render_template('to_do.html', msg=msg)



########### Class Task Form ###########################
class TaskForm(Form):
	task = StringField('Task', [validators.Length(min=1, max=50)])


########### Add Task Route ###########################
@app.route('/add_task', methods=['GET', 'POST'])
@is_logged_in
def add_task():
	form = TaskForm(request.form)
	if request.method == 'POST' and form.validate():
		task = form.task.data
		add_task = Tasks(session['username'], task, 1)
		db.session.add(add_task)
		db.session.commit()	
		flash('Task Added', 'success')
		return redirect(url_for('to_do'))

	return render_template('add_task.html',form=form)


########### Task Completed Route ###########################
@app.route('/task_completed/<string:id>', methods=['POST'])
@is_logged_in
def task_completed(id):
	complete_task = Tasks.query.get(id)
	complete_task.status = 0
	db.session.commit()
	flash('Task Completed', 'success')
	return redirect(url_for('to_do'))

########### Readd-task  Route ###########################
@app.route('/readd_task/<string:id>', methods=['POST'])
@is_logged_in
def readd_task(id):
	readd_task = Tasks.query.get(id)
	readd_task.status = 1
	db.session.commit()
	flash('Task Added', 'success')
	return redirect(url_for('to_do'))


########### Forgot password ###########################

class EmailForm(Form):
    email = StringField('Email', [validators.Length(min=6, max=40)])
    

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
	form = EmailForm(request.form)

	if request.method == 'POST' and form.validate():

	 	found_user = Users.query.filter_by(email=form.email.data).first() 

	 	if(found_user):
	 		msg = Message('Password Request', sender = 'amcp37@gmail.com', recipients = [form.email.data])
	 		msg.body = "Reset the password using this link"
	 		msg.html = render_template('reset_pass_email.html', user=found_user)
	 		mail.send(msg)
	 		flash('Email Sent', 'success')
	 		return redirect(url_for('login'))
	return render_template('forgot_password.html', form=form)


########### Class Reset Form ###########################
class ResetForm(Form):
	reset = PasswordField('Password', [
		validators.DataRequired(),
		validators.Length(min=6, max=40),
		validators.EqualTo('confirm_reset', message='Passwords do not match')
	])

	confirm_reset = PasswordField('Confirm Password')


########### Reset Route ###########################
@app.route('/reset/<string:id>/', methods=['GET', 'POST'])
def reset(id):	

	form = ResetForm(request.form)
	
	if request.method == 'POST' and form.validate():
		user = Users.query.filter_by(id=id).first()
		user.password = sha256_crypt.encrypt(str(form.reset.data))
		db.session.add(user)
		db.session.commit()
		flash('Password Updated', 'success')
		return redirect(url_for('login'))

	return render_template('reset.html', form=form, id=id)


########### ErrorHandler page ###########################
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


########### Main ###########################
if __name__ == '__main__':
	app.secret_key = 'secret123'
	app.run()