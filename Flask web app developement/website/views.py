# views.py

from flask import Blueprint, request, render_template, flash, redirect, url_for, jsonify
from .models import User, db, Note
from flask_bcrypt import Bcrypt
from flask_login import login_user, logout_user, current_user, login_required
import json


views = Blueprint('views', __name__)

bcrypt = Bcrypt()

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == "POST":
        note = request.form.get('note')

        if len(note) < 1:
            flash('add note!', category='error')
        else:
            new_note = Note(data=note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Note added!', category='success')
    
    return render_template('home.html' , user=current_user)

@views.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            flash('Logged in Successfully', category='success')
            login_user(user)
            return redirect(url_for('views.home'))
        else:
            flash('Invalid email or password, try again', category='error')

    return render_template("login.html")

# views.py





@views.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('views.login'))

@views.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Account already exists, please log in', category='error')
        elif len(email) < 4 or len(firstName) < 1 or any(char.isdigit() for char in firstName):
            flash('Invalid input. Check email and first name.', category='error')
        elif password2 != password1 or len(password1) < 7:
            flash('Passwords do not match or are too short', category='error')
        else:
            hashed_password = bcrypt.generate_password_hash(password1).decode('utf-8')
            new_user = User(email=email, firstName=firstName, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash('Welcome! Account created successfully', category='success')
            return redirect(url_for('views.home'))

    return render_template("signup.html")


@views.route('/delete-note', methods=['POST'])
def delete_note():
    note = json.loads(request.data)
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()
    return jsonify({})