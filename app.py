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

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
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
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        usertype = request.form.get('usertype')

        print(
            f"Debug: Received data - Username: {username}, Password: {password}, Email: {email}, UserType: {usertype}")

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('signup'))

        print("Debug: Creating new user...")
        new_user = User(username=username, email=email, usertype=usertype)
        new_user.password = password  # This uses the setter we defined
        db.session.add(new_user)
        db.session.commit()
        print(f"Debug: User {username} created successfully!")

        flash('Successfully signed up! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


if __name__ == "__main__":
    app.run(debug=True)
