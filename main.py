from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'secret123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///helpdesk.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='staff')  # 'admin' or 'staff'
    tickets = db.relationship('Ticket', backref='creator', lazy=True)


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='open')  # 'open' or 'closed'
    priority = db.Column(db.String(20), nullable=False, default='medium')  # 'low', 'medium', 'high'
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    replies = db.relationship('Reply', backref='ticket', lazy=True, cascade='all, delete-orphan')


class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user = db.relationship('User', backref='replies')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            tickets = Ticket.query.order_by(Ticket.created_at.desc()).all()
        else:
            tickets = Ticket.query.filter_by(user_id=current_user.id).order_by(Ticket.created_at.desc()).all()
        return render_template('dashboard.html', tickets=tickets)
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/create_ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        priority = request.form['priority']

        ticket = Ticket(
            title=title,
            description=description,
            priority=priority,
            user_id=current_user.id
        )
        db.session.add(ticket)
        db.session.commit()
        flash('Ticket created successfully!')
        return redirect(url_for('index'))

    return render_template('create_ticket.html')


@app.route('/ticket/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    # Check if user can view this ticket
    if current_user.role != 'admin' and ticket.user_id != current_user.id:
        flash('You do not have permission to view this ticket.')
        return redirect(url_for('index'))

    replies = Reply.query.filter_by(ticket_id=ticket_id).order_by(Reply.created_at.asc()).all()
    return render_template('view_ticket.html', ticket=ticket, replies=replies)


@app.route('/ticket/<int:ticket_id>/reply', methods=['POST'])
@login_required
def reply_to_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    # Check if user can reply to this ticket
    if current_user.role != 'admin' and ticket.user_id != current_user.id:
        flash('You do not have permission to reply to this ticket.')
        return redirect(url_for('index'))

    content = request.form['content']
    reply = Reply(
        content=content,
        user_id=current_user.id,
        ticket_id=ticket_id
    )
    db.session.add(reply)
    db.session.commit()
    flash('Reply added successfully!')
    return redirect(url_for('view_ticket', ticket_id=ticket_id))


@app.route('/ticket/<int:ticket_id>/close')
@login_required
def close_ticket(ticket_id):
    if current_user.role != 'admin':
        flash('Only administrators can close tickets.')
        return redirect(url_for('index'))

    ticket = Ticket.query.get_or_404(ticket_id)
    ticket.status = 'closed'
    db.session.commit()
    flash('Ticket closed successfully!')
    return redirect(url_for('view_ticket', ticket_id=ticket_id))


def create_admin_user():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()


def create_sample_staff():
    staff = User.query.filter_by(username='staff').first()
    if not staff:
        staff = User(
            username='staff',
            password_hash=generate_password_hash('staff123'),
            role='staff'
        )
        db.session.add(staff)
        db.session.commit()


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
        create_sample_staff()
    app.run(host='0.0.0.0', port=5050, debug=True)
