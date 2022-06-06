from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from forms import RegisterForm, LoginForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask import abort

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, ForeignKey, String

from dotenv import load_dotenv
import os

load_dotenv()
SECRET_KEY = os.getenv("secret_key")

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///TODO.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
Base = declarative_base()


class Users(UserMixin, db.Model):
	__tablename__ = "users"
	id = Column(Integer, primary_key=True)
	email = Column(String, nullable=False)
	password = Column(String, nullable=False)

	tasks_active = relationship("Active_Tasks", back_populates="active")
	tasks_completed = relationship("Completed_Tasks", back_populates="completed")


class Active_Tasks(db.Model):
	__tablename__ = "active_tasks"
	id = Column(Integer, primary_key=True)
	deadline = Column(String, nullable=False)
	title = Column(String, nullable=False)
	description = Column(String, nullable=False)
	priority = Column(String, nullable=False)

	user_id = Column(Integer, ForeignKey("users.id"))
	active = relationship("Users", back_populates="tasks_active")


class Completed_Tasks(db.Model):
	__tablename__ = "completed_tasks"
	id = Column(Integer, primary_key=True)
	deadline = Column(String, nullable=False)
	title = Column(String, nullable=False)
	description = Column(String, nullable=False)
	priority = Column(String, nullable=False)

	user_id = Column(Integer, ForeignKey("users.id"))
	completed = relationship("Users", back_populates="tasks_completed")


@login_manager.user_loader
def load_user(user_id):
	return Users.query.get(int(user_id))


@app.route("/")
def home():
	return render_template("index.html")


@app.route("/active_tasks", methods=["GET", "POST"])
def active_tasks():
	if current_user.is_authenticated:
		tasks_all = Active_Tasks.query.filter_by(user_id=current_user.id).all()
		status = "active"
		return render_template("active.html", active_tasks=tasks_all, task_status=status)
	else:
		return redirect(url_for("login"))


@app.route("/completed_tasks", methods=["GET", "POST"])
def completed_tasks():
	tasks_all = Completed_Tasks.query.filter_by(user_id=current_user.id).all()
	status = "completed"
	return render_template("completed.html", completed_tasks=tasks_all, task_status=status)


@app.route("/add_task", methods=["GET", "POST"])
def add_task():
	if current_user.is_authenticated:
		if request.method == "POST":
			deadline = request.form.get("deadline")
			title = request.form.get("title")
			description = request.form.get("description")
			priority = request.form.get("priority")
			new_task_active = Active_Tasks(
				deadline=deadline,
				title=title,
				description=description,
				priority=priority,
				user_id=current_user.id
			)
			db.session.add(new_task_active)
			db.session.commit()
			return redirect(url_for("active_tasks"))
		return render_template("add_task.html")
	else:
		return redirect(url_for("login"))


@app.route("/<id>", methods=["GET", "POST"])
def complete_task(id):
	current_task = Active_Tasks.query.filter_by(id=id).first()
	if current_task:
		new_completed = Completed_Tasks(
			deadline=current_task.deadline,
			title=current_task.title,
			description=current_task.description,
			priority=current_task.priority,
			user_id=current_user.id
		)
		db.session.add(new_completed)
		Active_Tasks.query.filter_by(id=id, user_id=current_user.id).delete()
		db.session.commit()
		return redirect(url_for('active_tasks'))
	return redirect(url_for("active_tasks"))


@app.route("/<id>/<status>", methods=["GET", "POST"])
def delete_task(id, status):
	if status == "active":
		Active_Tasks.query.filter_by(id=id, user_id=current_user.id).delete()
		db.session.commit()
		return redirect(url_for("active_tasks"))
	elif status == "completed":
		Completed_Tasks.query.filter_by(id=id, user_id=current_user.id).delete()
		db.session.commit()
		return redirect(url_for("completed_tasks"))
	else:
		pass


@app.route("/<id>/", methods=["GET", "POST"])
def set_active(id):
	task_to_send = Completed_Tasks.query.filter_by(id=id, user_id=current_user.id).first()
	new_active_task = Active_Tasks(
		deadline=task_to_send.deadline,
		title=task_to_send.title,
		description=task_to_send.description,
		priority=task_to_send.priority,
		user_id=current_user.id
	)
	db.session.add(new_active_task)
	db.session.commit()

	Completed_Tasks.query.filter_by(id=id, user_id=current_user.id).delete()
	db.session.commit()
	return redirect(url_for("active_tasks"))


def check_user(id, status):
	if status == "active":
		task_to_change = Active_Tasks.query.filter_by(id=id).first()
		if task_to_change.user_id != current_user.id:
			print("unauthorized attempt by user")
			abort(403)
	if status == "completed":
		task_to_change = Completed_Tasks.query.filter_by(id=id).first()
		if task_to_change.user_id != current_user.id:
			print("unauthorized attempt by user")
			abort(403)


@app.route("/edit_task/<id>/<status>", methods=["GET", "POST"])
def edit_task_page(id, status):
	check_user(id, status)
	if status == "active":
		send_status = "active"
		current_active_task = Active_Tasks.query.filter_by(id=id, user_id=current_user.id).first()
		return render_template("edit_page.html", id=id, status=send_status, task=current_active_task)

	elif status == "completed":
		send_status = "completed"
		current_completed_task = Completed_Tasks.query.filter_by(id=id, user_id=current_user.id).first()
		return render_template("edit_page.html", id=id, status=send_status, task=current_completed_task)


@app.route("/edit_current_task/<id>/<status>", methods=["GET", "POST"])
def edit_current_task(id, status):
	if request.method == "POST":
		if status == "active":
			current_task = Active_Tasks.query.filter_by(id=id, user_id=current_user.id).first()
			if request.method == "POST":
				current_task.deadline = request.form.get("deadline")
				current_task.title = request.form.get("title")
				current_task.description = request.form.get("description")
				current_task.priority = request.form.get("priority")
				db.session.commit()
				return redirect(url_for("active_tasks"))

		if status == "completed":
			current_task = Completed_Tasks.query.filter_by(id=id, user_id=current_user.id).first()
			if request.method == "POST":
				current_task.deadline = request.form.get("deadline")
				current_task.title = request.form.get("title")
				current_task.description = request.form.get("description")
				current_task.priority = request.form.get("priority")
				db.session.commit()
				return redirect(url_for("completed_tasks"))
	else:
		return redirect(url_for("active_tasks"))


@app.route("/login", methods=["GET", "POST"])
def login():
	if current_user.is_authenticated:
		return redirect(url_for("active_tasks"))
	else:
		form = LoginForm()
		if request.method == "POST":
			email = request.form.get("email")
			user = Users.query.filter_by(email=email).first()
			if user:
				password = request.form.get("password")
				if check_password_hash(user.password, password):
					login_user(user)
					return redirect(url_for("active_tasks"))
				else:
					flash("incorrect password, please try again")
			else:
				flash("We don't have a user associated with this email, please try again.")
				return redirect(url_for("login"))
		return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
	form = RegisterForm()
	if request.method == "POST":
		email = request.form.get("email")
		user = Users.query.filter_by(email=email).first()
		if user:
			flash("You've already registered with that email address, please log in")
		else:
			hashed_and_salted_pw = generate_password_hash(
				password=request.form.get("password"),
				method="pbkdf2:sha256",
				salt_length=8
			)
			new_user = Users(
				email=request.form.get("email"),
				password=hashed_and_salted_pw
			)

			db.session.add(new_user)
			db.session.commit()
			login_user(new_user)
			return redirect(url_for("active_tasks"))
	return render_template("register.html", form=form)


@app.route("/logout", methods=["GET", "POST"])
def logout():
	logout_user()
	return redirect(url_for("home"))


if __name__ == "__main__":
	app.run(port=5000, debug=True, host="localhost")
