from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy.dialects.postgresql import ENUM

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisshouldbesecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://brandontiong:BT2129bt@localhost:5432/sponsorin'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(UserMixin, db.Model):
    __tablename__ = 'appuser'
    userid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    usertype = db.Column(ENUM('Admin', 'Company', 'Athlete', name='usertype'), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

    def get_id(self):
        return str(self.userid)

class Profile(db.Model):
    __tablename__ = 'profile'
    ProfileID = db.Column(db.Integer, primary_key=True)
    UserID = db.Column(db.Integer, db.ForeignKey('appuser.userid'), unique=True)
    FullName = db.Column(db.String(100))
    Bio = db.Column(db.Text)
    Gender = db.Column(ENUM('Male', 'Female', 'Other', name='gendertype'))
    SportsCategory = db.Column(db.String(50))
    ProfilePicture = db.Column(db.Text)
    VerifiedStatus = db.Column(db.Boolean, default=False)

class Message(db.Model):
    __tablename__ = 'message'
    MessageID = db.Column(db.Integer, primary_key=True)
    SenderID = db.Column(db.Integer, db.ForeignKey('appuser.UserID'))
    ReceiverID = db.Column(db.Integer, db.ForeignKey('appuser.UserID'))
    Content = db.Column(db.Text)
    Timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

class Offer(db.Model):
    __tablename__ = 'offer'
    OfferID = db.Column(db.Integer, primary_key=True)
    CompanyID = db.Column(db.Integer, db.ForeignKey('profile.ProfileID'))
    AthleteID = db.Column(db.Integer, db.ForeignKey('profile.ProfileID'))
    Details = db.Column(db.Text)
    Status = db.Column(ENUM('Pending', 'Accepted', 'Declined', 'Counter-offered', name='offerstatus'), default='Pending')

class Watchlist(db.Model):
    __tablename__ = 'watchlist'
    WatchlistID = db.Column(db.Integer, primary_key=True)
    CompanyID = db.Column(db.Integer, db.ForeignKey('profile.ProfileID'))
    AthleteID = db.Column(db.Integer, db.ForeignKey('profile.ProfileID'))
    SportsCategory = db.Column(db.String(50))

@app.route('/index', methods=['GET'])
def index():
    return render_template('index.html')
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check your username and password', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return "Logged in as: " + current_user.username

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))




if __name__ == "__main__":
    app.run(debug=True)
