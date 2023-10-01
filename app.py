from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy.dialects.postgresql import ENUM
from werkzeug.utils import secure_filename
from sqlalchemy import and_
from werkzeug.security import check_password_hash
from PIL import Image
from sqlalchemy.orm import relationship
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisshouldbesecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://brandontiong:BT2129bt@localhost:5432/sponsorin'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

UPLOAD_FOLDER = 'static/profile_picture'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

class User(UserMixin, db.Model):
    __tablename__ = 'appuser'
    userid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    usertype = db.Column(ENUM('Admin', 'Company', 'Athlete', name='usertype'), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    profile = relationship('Profile', backref='appuser', lazy=True, uselist=False)

    def get_id(self):
        return str(self.userid)

class Profile(db.Model):
    __tablename__ = 'profile'
    profileid = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, db.ForeignKey('appuser.userid'), unique=True)
    fullname = db.Column(db.String(100))
    bio = db.Column(db.Text)
    gender = db.Column(ENUM('Male', 'Female', 'Other', name='gendertype'))
    sportscategory = db.Column(db.String(50))
    profilepicture = db.Column(db.Text)
    verifiedstatus = db.Column(db.Boolean, default=False)
    userid = db.Column(db.Integer, db.ForeignKey('appuser.userid'), unique=True)

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
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
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
    profile_exists = Profile.query.filter_by(userid=current_user.userid).first() is not None
    profile = Profile.query.filter_by(userid=current_user.userid).first()
    return render_template('dashboard.html', profile_exists=profile_exists, profile=profile)

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
        new_user.password = password
        db.session.add(new_user)
        db.session.commit()
        print(f"Debug: User {username} created successfully!")

        flash('Successfully signed up! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/create_profile', methods=['GET', 'POST'])
@login_required
def create_profile():
    existing_profile = Profile.query.filter_by(userid=current_user.userid).first()
    if existing_profile:
        flash('You already have a profile!', 'info')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        bio = request.form.get('bio')
        gender = request.form.get('gender')
        sports_category = request.form.get('sports_category')

        profile_picture = request.files.get('profile_picture')
        filepath = None
        if profile_picture and allowed_file(profile_picture.filename):
            filename = secure_filename(profile_picture.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            with Image.open(profile_picture) as img:
                img = img.resize((256, 256))
                img.save(filepath)

            # Updated code to save relative path into the database
            relative_filepath = os.path.join('profile_picture', filename)
            filepath = relative_filepath  # overwrite the filepath variable with the relative path

        new_profile = Profile(
            userid=current_user.userid,
            fullname=full_name,
            bio=bio,
            gender=gender,
            sportscategory=sports_category,
            profilepicture=filepath  # this now uses the relative path
        )
        db.session.add(new_profile)
        db.session.commit()
        flash('Profile created successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_profile.html')


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    profile = Profile.query.filter_by(userid=current_user.userid).first()
    if not profile:
        flash('No profile found!', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        profile.fullname = request.form.get('full_name')
        profile.bio = request.form.get('bio')
        profile.gender = request.form.get('gender')
        profile.sportscategory = request.form.get('sports_category')

        profile_picture = request.files.get('profile_picture')
        if profile_picture and allowed_file(profile_picture.filename):
            filename = secure_filename(profile_picture.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)


            with Image.open(profile_picture) as img:

                img = img.resize((256, 256))

                img.save(filepath)

            relative_filepath = os.path.join('profile_picture', filename)
            profile.profilepicture = relative_filepath

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_profile.html', profile=profile)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
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

            return redirect(url_for('uploaded_file', filename=filename))


@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    profile = Profile.query.filter_by(userid=current_user.userid).first()
    user = User.query.get(current_user.userid)

    if request.method == 'POST':

        if profile:
            db.session.delete(profile)


        db.session.delete(user)
        db.session.commit()

        flash('Your account and profile have been deleted', 'success')
        return redirect(url_for('goodbye'))

    return render_template('delete_account.html')
@app.route('/goodbye')
def goodbye():
    return render_template('goodbye.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.usertype != 'Admin':
        flash('Permission Denied: You are not an administrator', 'danger')
        return redirect(url_for('index'))
    unverified_profiles = Profile.query.filter_by(verifiedstatus=False).all()
    users = User.query.all()  # Retrieve all users from the database
    return render_template('admin_dashboard.html', unverified_profiles=unverified_profiles, users=users)



@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.usertype != 'Admin':
        flash('Permission Denied: You are not an administrator', 'danger')
        return redirect(url_for('index'))

    user = User.query.get(user_id)
    if user is None:
        flash('User not found', 'danger')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        new_password = request.form.get('password')


        if new_password:
            user.password = new_password


        new_usertype = request.form.get('usertype')
        if new_usertype and new_usertype in ['Admin', 'Company', 'Athlete']:
            user.usertype = new_usertype


        db.session.commit()
        flash(f'Successfully edited {user.username}', 'success')
        return redirect(url_for('admin_dashboard'))


    return render_template('user_edit.html', user=user)

@app.route('/admin/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):

    if current_user.usertype != 'Admin':
        flash('Permission Denied: You are not an administrator', 'danger')
        return redirect(url_for('index'))

    user = User.query.get(user_id)

    if user is None:
        flash('User not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    db.session.delete(user)
    db.session.commit()
    flash(f'Successfully deleted {user.username}', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/unverified_profiles')
@login_required
def unverified_profiles_page():
    if current_user.usertype != 'Admin':
        flash('Permission Denied: You are not an administrator', 'danger')
        return redirect(url_for('index'))

    unverified_profiles = Profile.query.filter_by(verifiedstatus=False).all()
    return render_template('unverified_profiles.html', unverified_profiles=unverified_profiles)
@app.route('/verify_profile/<int:profile_id>', methods=['GET', 'POST'])
@login_required
def verify_profile(profile_id):

    profile = Profile.query.get(profile_id)
    if profile is None:
        flash('Profile not found', 'danger')
        return redirect(url_for('unverified_profiles_page'))

    profile.verifiedstatus = True
    db.session.commit()

    flash('Profile successfully verified', 'success')
    return redirect(url_for('unverified_profiles_page'))
@app.route('/admin/user_list', methods=['GET', 'POST'])
@login_required
def user_list_page():
    if current_user.usertype != 'Admin':
        flash('Permission Denied: You are not an administrator', 'danger')
        return redirect(url_for('index'))

    search = request.form.get('search')
    usertype_filter = request.form.get('usertype_filter')
    gender_filter = request.form.get('gender_filter')
    verification_filter = request.form.get('verification_filter')


    filter_conditions = []

    if search:
        filter_conditions.append(User.username.ilike(f"%{search}%"))

    if usertype_filter:
        filter_conditions.append(User.usertype == usertype_filter)

    if gender_filter:

        filter_conditions.append(Profile.gender == gender_filter)

    if verification_filter:
        verified_status = True if verification_filter == "Verified" else False
        filter_conditions.append(Profile.verifiedstatus == verified_status)



    users = User.query.join(Profile, User.userid == Profile.userid, isouter=True).filter(and_(*filter_conditions)).all()

    return render_template('user_list.html', users=users)


@app.route('/admin/add_admin', methods=['GET', 'POST'])
@login_required
def add_admin():
    if current_user.usertype != 'Admin':
        flash('Permission Denied: You are not an administrator', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        new_admin = User(username=username, password=password, email=email, usertype='Admin')
        db.session.add(new_admin)
        db.session.commit()

        flash('New admin user successfully created!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_admin.html')

if __name__ == "__main__":
    app.run(debug=True)
