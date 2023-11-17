from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from sqlalchemy import and_
from werkzeug.security import check_password_hash
from PIL import Image
from sqlalchemy.exc import IntegrityError
from sqlalchemy import Column, or_,Integer, String, Text, ForeignKey, Boolean, Enum, TIMESTAMP, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from flask import jsonify
from sqlalchemy.orm import aliased
from sqlalchemy.orm import joinedload
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisshouldbesecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:e@localhost:5432/sponsorIn'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

UPLOAD_FOLDER = os.path.join('static', 'profile_picture')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

class User(UserMixin, db.Model):
    __tablename__ = 'appuser'
    userid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    usertype = db.Column(Enum('Admin', 'Company', 'Athlete', name='usertype'), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    profile = relationship('Profile', backref='appuser', uselist=False, cascade="all, delete-orphan")

    def get_id(self):
        return str(self.userid)

class Profile(db.Model):
    __tablename__ = 'profile'
    profileid = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, ForeignKey('appuser.userid', ondelete='CASCADE'), unique=True)
    fullname = db.Column(db.String(100))
    bio = db.Column(db.Text)
    profilepicture = db.Column(db.Text)
    verifiedstatus = db.Column(db.Boolean, default=False)
    athlete_profile = relationship('AthleteProfile', backref='profile', uselist=False, cascade="all, delete-orphan")
    company_profile = db.relationship('CompanyProfile', backref='profile', uselist=False, cascade="all, delete-orphan")

class College(db.Model):
    __tablename__ = 'college'
    collegeid = db.Column(db.Integer, primary_key=True)
    collegename = db.Column(db.String(100), unique=True, nullable=False)
    athletes = relationship('AthleteProfile', backref='college')

class AthleteProfile(db.Model):
    __tablename__ = 'athleteprofile'
    athleteprofileid = db.Column(db.Integer, primary_key=True)
    profileid = db.Column(db.Integer, db.ForeignKey('profile.profileid', ondelete='CASCADE'), unique=True)
    gender = db.Column(Enum('Male', 'Female', 'Other', name='gendertype'))
    sportscategory = db.Column(Enum('Basketball', 'Football', 'Soccer', name='sportscategorytype'))
    collegeid = db.Column(db.Integer, ForeignKey('college.collegeid'))

class CompanyProfile(db.Model):
    __tablename__ = 'companyprofile'
    companyprofileid = db.Column(db.Integer, primary_key=True)
    profileid = db.Column(db.Integer, ForeignKey('profile.profileid', ondelete='CASCADE'), unique=True)
    companyname = db.Column(db.String(100), nullable=False)
    companylogo = db.Column(db.Text)


class Message(db.Model):
    __tablename__ = 'message'
    messageid = db.Column(db.Integer, primary_key=True)
    senderid = db.Column(db.Integer, ForeignKey('appuser.userid'))
    receiverid = db.Column(db.Integer, ForeignKey('appuser.userid'))
    content = db.Column(db.Text)
    timestamp = db.Column(db.TIMESTAMP, default=db.func.current_timestamp())

class Offer(db.Model):
    __tablename__ = 'offer'
    offerid = db.Column(db.Integer, primary_key=True)
    companyid = db.Column(db.Integer, ForeignKey('companyprofile.companyprofileid'))
    athleteid = db.Column(db.Integer, ForeignKey('athleteprofile.athleteprofileid'))
    details = db.Column(db.Text)
    status = db.Column(Enum('Pending', 'Accepted', 'Declined', 'Counter-offered', name='offerstatus'), default='Pending')
    last_updated_by = db.Column(Enum('Company', 'Athlete', name='updatedbytype'), nullable=True)

class Watchlist(db.Model):
    __tablename__ = 'watchlist'
    watchlistid = db.Column(db.Integer, primary_key=True)
    companyid = db.Column(db.Integer, ForeignKey('companyprofile.companyprofileid'))
    athleteid = db.Column(db.Integer, ForeignKey('athleteprofile.athleteprofileid'))
    sportscategory = db.Column(Enum('Basketball', 'Football', 'Soccer', name='sportscategorytype'))

class Sponsorship(db.Model):
    __tablename__ = 'sponsorship'
    sponsorshipid = db.Column(db.Integer, primary_key=True)
    companyid = db.Column(db.Integer, ForeignKey('companyprofile.companyprofileid'))
    athleteid = db.Column(db.Integer, ForeignKey('athleteprofile.athleteprofileid'))
    startdate = db.Column(db.TIMESTAMP, default=db.func.current_timestamp())
    enddate = db.Column(db.TIMESTAMP)
    details = db.Column(db.Text)


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.usertype == 'Admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            if user.usertype == 'Admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check your username and password', 'danger')
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.usertype == 'Admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.usertype == 'Company':
        return redirect(url_for('company_dashboard'))

    profile = Profile.query.filter_by(userid=current_user.userid).first()
    profile_exists = profile is not None
    athlete_profile = None
    company_profile = None

    if profile_exists:
        if current_user.usertype == 'Athlete':
            athlete_profile = AthleteProfile.query.filter_by(profileid=profile.profileid).first()

    offers = Offer.query.filter_by(athleteid=current_user.userid, status='Pending').all()

    return render_template('dashboard.html', profile=profile, athlete_profile=athlete_profile, company_profile=company_profile, profile_exists=profile_exists, offers=offers)

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


from sqlalchemy.orm import aliased

@app.route('/view_company', methods=['GET', 'POST'])
@login_required
def view_company():
    if request.method == 'POST':
        search_term = request.form.get('search', '').strip()
        verified_companies = db.session.query(CompanyProfile, Profile.userid) \
            .join(Profile, CompanyProfile.profileid == Profile.profileid) \
            .filter(Profile.verifiedstatus == True) \
            .filter(
            or_(CompanyProfile.companyname.ilike(f"%{search_term}%"), Profile.fullname.ilike(f"%{search_term}%"))) \
            .all()
    else:
        verified_companies = db.session.query(CompanyProfile, Profile.userid) \
            .join(Profile, CompanyProfile.profileid == Profile.profileid) \
            .filter(Profile.verifiedstatus == True) \
            .all()

    return render_template('view_company.html', companies=verified_companies)

@app.route('/view_single_company/<int:company_id>')
@login_required
def view_single_company(company_id):
    company = CompanyProfile.query.get_or_404(company_id)
    sponsored_athletes = []

    sponsorships = Sponsorship.query.filter_by(companyid=company.companyprofileid).all()
    for sponsorship in sponsorships:
        athlete_profile = AthleteProfile.query.get(sponsorship.athleteid)
        if athlete_profile:
            sponsored_athletes.append(Profile.query.get(athlete_profile.profileid))

    return render_template('company_detail.html', company=company, sponsored_athletes=sponsored_athletes)

@app.route('/contact_support')
@login_required
def contact_support():
    admin_users = User.query.filter_by(usertype='Admin').all()
    return render_template('contact_support.html', users=admin_users)


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

        new_profile = Profile(
            userid=current_user.userid,
            fullname=full_name,
            bio=bio,
            profilepicture = 'profile_picture/defualtpicture.png'
        )
        db.session.add(new_profile)
        db.session.flush()

        if current_user.usertype == 'Athlete':
            college_id = request.form.get('college')
            college = College.query.get(college_id)
            if not college:
                flash('Selected college does not exist!', 'danger')
                return redirect(url_for('create_profile'))

            athlete_profile = AthleteProfile(
                profileid=new_profile.profileid,
                gender=request.form.get('gender'),
                sportscategory=request.form.get('sports_category'),
                collegeid=college_id

            )
            db.session.add(athlete_profile)

        elif current_user.usertype == 'Company':
            company_name = request.form.get('company_name')
            company_logo = request.form.get('company_logo')

            company_profile = CompanyProfile(
                profileid=new_profile.profileid,
                companyname=company_name,
                companylogo=company_logo
            )
            db.session.add(company_profile)

        db.session.commit()

        flash('Profile created successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_profile.html', user_type=current_user.usertype)


@app.route('/get_colleges')
def get_colleges():
    search_term = request.args.get('q', '')
    matching_colleges = College.query.filter(College.collegename.ilike(f'%{search_term}%')).all()
    college_list = [{'id': college.collegeid, 'text': college.collegename} for college in matching_colleges]

    return jsonify(results=college_list)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    profile = Profile.query.filter_by(userid=current_user.userid).first()
    if not profile:
        flash('No profile found!', 'danger')
        return redirect(url_for('dashboard'))

    athlete_profile = AthleteProfile.query.filter_by(profileid=profile.profileid).first()
    company_profile = CompanyProfile.query.filter_by(profileid=profile.profileid).first()

    if request.method == 'POST':
        profile.fullname = request.form.get('full_name')
        profile.bio = request.form.get('bio')

        profile_picture = request.files.get('profile_picture')
        if profile_picture and allowed_file(profile_picture.filename):
            filename = secure_filename(profile_picture.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            with Image.open(profile_picture) as img:
                img = img.resize((256, 256))
                img.save(filepath)

            relative_filepath = os.path.join('profile_picture', filename)
            profile.profilepicture = relative_filepath

        if current_user.usertype == 'Athlete':
            athlete_profile.gender = request.form.get('gender')
            athlete_profile.sportscategory = request.form.get('sports_category')
            athlete_profile.collegeid = request.form.get('college')

        if current_user.usertype == 'Company':
            if not company_profile:
                company_profile = CompanyProfile(profileid=profile.profileid,
                                                 companyname=request.form.get('company_name'))
                db.session.add(company_profile)
            else:
                company_profile.companyname = request.form.get('company_name')

            company_logo = request.files.get('company_logo')
            if company_logo and allowed_file(company_logo.filename):
                filename = secure_filename(company_logo.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                with Image.open(company_logo) as img:
                    img = img.resize((256, 256))
                    img.save(filepath)

                relative_filepath = os.path.join('profile_picture', filename)
                company_profile.companylogo = relative_filepath

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    colleges = College.query.all()
    return render_template('edit_profile.html', profile=profile, athlete_profile=athlete_profile, company_profile=company_profile, colleges=colleges)


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
    user = User.query.get(current_user.userid)

    if request.method == 'POST':
        if user:
            profile = Profile.query.filter_by(userid=current_user.userid).first()

            if profile:
                athlete_profile = AthleteProfile.query.filter_by(profileid=profile.profileid).first()
                company_profile = CompanyProfile.query.filter_by(profileid=profile.profileid).first()

                if athlete_profile:
                    db.session.delete(athlete_profile)
                elif company_profile:
                    db.session.delete(company_profile)

                db.session.delete(profile)

            db.session.delete(user)
            db.session.commit()

            flash('Your account and profile have been deleted', 'success')
            return redirect(url_for('goodbye'))

    return render_template('delete_account.html')
@app.route('/goodbye')
def goodbye():
    return render_template('goodbye.html')


@app.route('/company_dashboard')
@login_required
def company_dashboard():
    if current_user.usertype != 'Company':
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))

    profile = Profile.query.filter_by(userid=current_user.userid).first()
    profile_exists = profile is not None
    company_profile = None

    if profile_exists:
        company_profile = CompanyProfile.query.filter_by(profileid=profile.profileid).first()

    return render_template('company_dashboard.html', profile=profile, company_profile=company_profile, profile_exists=profile_exists)


@app.route('/company_dashboard/watchlist')
@login_required
def view_watchlist():
    company_profile = CompanyProfile.query.filter_by(profileid=current_user.profile.profileid).first()


    watchlist_athletes = db.session.query(AthleteProfile, Profile) \
        .join(Profile, AthleteProfile.profileid == Profile.profileid) \
        .join(Watchlist, Watchlist.athleteid == AthleteProfile.athleteprofileid) \
        .filter(Watchlist.companyid == company_profile.companyprofileid).all()

    return render_template('watchlist.html', watchlist_athletes=watchlist_athletes)


@app.route('/add_to_watchlist/<int:user_id>', methods=['POST'])
@login_required
def add_to_watchlist(user_id):

    user = User.query.get(user_id)
    if not user or user.usertype != 'Athlete':
        flash('The athlete does not exist.', 'warning')
        return redirect(url_for('view_athletes'))

    athlete = user.profile.athlete_profile
    if not athlete:
        flash('The athlete profile does not exist.', 'warning')
        return redirect(url_for('view_athletes'))

    company = CompanyProfile.query.filter_by(profileid=current_user.profile.profileid).first()
    if not company:
        flash('Only companies can add to the watchlist.', 'warning')
        return redirect(url_for('view_athletes'))

    already_added = Watchlist.query.filter_by(companyid=company.companyprofileid, athleteid=athlete.athleteprofileid).first()
    if already_added:
        flash('This athlete is already in your watchlist.', 'info')
        return redirect(url_for('view_athlete', user_id=user_id))

    new_watchlist_item = Watchlist(companyid=company.companyprofileid, athleteid=athlete.athleteprofileid)
    try:
        db.session.add(new_watchlist_item)
        db.session.commit()
        flash('Athlete added to watchlist successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while adding the athlete to the watchlist.', 'danger')

    return redirect(url_for('view_athlete', user_id=user_id))


@app.route('/remove_from_watchlist/<int:athlete_id>', methods=['POST'])
@login_required
def remove_from_watchlist(athlete_id):

    if current_user.usertype != 'Company':
        flash('Only companies can remove athletes from watchlist!', 'danger')
        return redirect(url_for('company_dashboard'))

    company_profile = CompanyProfile.query.filter_by(profileid=current_user.profile.profileid).first()

    if not company_profile:
        flash('Company profile not found.', 'danger')
        return redirect(url_for('company_dashboard'))

    athlete_watchlist_entry = Watchlist.query.filter_by(companyid=company_profile.companyprofileid, athleteid=athlete_id).first()

    if not athlete_watchlist_entry:
        flash('Athlete not in your watchlist!', 'warning')
        return redirect(url_for('company_dashboard'))

    try:
        db.session.delete(athlete_watchlist_entry)
        db.session.commit()
        flash('Successfully removed athlete from watchlist!', 'success')
    except IntegrityError:
        db.session.rollback()
        flash('There was an error removing the athlete from the watchlist.', 'danger')
    return redirect(url_for('view_watchlist'))

@app.route('/view_athletes', methods=['GET', 'POST'])
@login_required
def view_athletes():
    current_company_profile = None
    if current_user.usertype == 'Company':
        current_company_profile = CompanyProfile.query.filter_by(profileid=current_user.profile.profileid).first()

    sponsored_athletes = []
    if current_company_profile:
        sponsored_athletes = [s.athleteid for s in Sponsorship.query.filter_by(companyid=current_company_profile.companyprofileid).all()]

    query = User.query.filter_by(usertype='Athlete').join(Profile, User.profile).filter(
        Profile.verifiedstatus == True).join(AthleteProfile)

    if request.method == 'POST':
        search_term = request.form.get('search')
        if search_term:
            query = query.filter(Profile.fullname.ilike(f"%{search_term}%"))

        gender_filter = request.form.get('gender_filter')
        if gender_filter:
            query = query.filter(AthleteProfile.gender == gender_filter)

        college_filter = request.form.get('college')
        if college_filter:
            query = query.filter(AthleteProfile.collegeid == college_filter)

        sports_category_filter = request.form.get('sportscategory')
        if sports_category_filter:
            query = query.filter(AthleteProfile.sportscategory == sports_category_filter)

    verified_athletes = query.all()
    colleges = College.query.all()
    sports_categories = [c.sportscategory for c in AthleteProfile.query.distinct(AthleteProfile.sportscategory).all()]

    return render_template('athlete_list_for_company.html', users=verified_athletes, colleges=colleges,
                           sports_categories=sports_categories, sponsored_athletes=sponsored_athletes)


@app.route('/athlete/<int:user_id>')
@login_required
def view_athlete(user_id):
    athlete = User.query.get_or_404(user_id)
    sponsorships = Sponsorship.query.filter_by(athleteid=athlete.profile.athlete_profile.athleteprofileid).all()
    sponsor_companies = [CompanyProfile.query.get(s.companyid).companyname for s in sponsorships]
    current_company_profile_id = CompanyProfile.query.filter_by(profileid=current_user.profile.profileid).first().companyprofileid
    is_in_watchlist = Watchlist.query.filter_by(athleteid=athlete.profile.athlete_profile.athleteprofileid,
                                                companyid=current_company_profile_id).first() is not None
    return render_template('athlete_detail.html', athlete=athlete, is_in_watchlist=is_in_watchlist,
                           sponsor_companies=sponsor_companies)


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.usertype != 'Admin':
        flash('Permission Denied: You are not an administrator', 'danger')
        return redirect(url_for('index'))

    unverified_profiles = Profile.query.filter_by(verifiedstatus=False).all()
    all_users = User.query.all()

    athletes = [user for user in all_users if user.usertype == 'Athlete'][:3]
    companies = [user for user in all_users if user.usertype == 'Company'][:3]

    return render_template('admin_dashboard.html', unverified_profiles=unverified_profiles, athletes=athletes, companies=companies)



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

    colleges = College.query.all()

    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')

        new_password = request.form.get('password')
        if new_password:
            user.password = new_password


        if user.usertype == 'Athlete' and user.profile and user.profile.athlete_profile:
            gender = request.form.get('gender')
            sportscategory = request.form.get('sportscategory')
            collegeid = request.form.get('collegeid')

            athlete_profile = user.profile.athlete_profile
            athlete_profile.gender = gender
            athlete_profile.sportscategory = sportscategory
            athlete_profile.collegeid = collegeid

        db.session.commit()
        flash(f'Successfully edited {user.username}', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('user_edit.html', user=user, colleges=colleges)

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


@app.route('/verify_user/<int:user_id>', methods=['POST'])
@login_required
def verify_user(user_id):
    if current_user.usertype != 'Admin':
        flash('Unauthorized action.', 'error')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    if user.profile:
        user.profile.verifiedstatus = True
        db.session.commit()
        flash('User verified successfully!', 'success')

        if user.usertype == 'Athlete':
            return redirect(url_for('user_list_page'))
        elif user.usertype == 'Company':
            return redirect(url_for('company_user_list_page'))  # Replace with your company list page route
    else:
        flash('Invalid user.', 'error')

    return redirect(url_for('dashboard'))

@app.route('/admin/user_list', methods=['GET', 'POST'])
@login_required
def user_list_page():
    if current_user.usertype != 'Admin':
        flash('Permission Denied: You are not an administrator', 'danger')
        return redirect(url_for('index'))

    search = request.form.get('search')
    gender_filter = request.form.get('gender_filter')
    verification_filter = request.form.get('verification_filter')

    filter_conditions = [User.usertype == 'Athlete']

    if search:
        filter_conditions.append(User.username.ilike(f"%{search}%"))

    if gender_filter:
        filter_conditions.append(AthleteProfile.gender == gender_filter)

    if verification_filter:
        verified_status = True if verification_filter == "Verified" else False
        filter_conditions.append(Profile.verifiedstatus == verified_status)

    users = User.query\
                .join(Profile, User.userid == Profile.userid, isouter=True)\
                .join(AthleteProfile, Profile.profileid == AthleteProfile.profileid, isouter=True)\
                .filter(and_(*filter_conditions)).all()

    return render_template('user_list.html', users=users)

@app.route('/admin/company_user_list', methods=['GET', 'POST'])
@login_required
def company_user_list_page():
    if current_user.usertype != 'Admin':
        flash('Permission Denied: You are not an administrator', 'danger')
        return redirect(url_for('index'))

    search = request.form.get('search')
    verification_filter = request.form.get('verification_filter')

    filter_conditions = []

    if search:
        filter_conditions.append(CompanyProfile.companyname.ilike(f"%{search}%"))

    if verification_filter and verification_filter != "":
        verified_status = True if verification_filter == "Verified" else False
        filter_conditions.append(Profile.verifiedstatus == verified_status)

    company_users = User.query.filter(User.usertype == 'Company')

    users = company_users\
                .join(Profile, User.userid == Profile.userid, isouter=True)\
                .join(CompanyProfile, Profile.profileid == CompanyProfile.profileid, isouter=True)\
                .filter(*filter_conditions).all()


    return render_template('company_user_list.html', users=users)


@app.route('/admin/admin_user_list', methods=['GET', 'POST'])
@login_required
def admin_user_list_page():
    if current_user.usertype != 'Admin':
        flash('Permission Denied: You are not an administrator', 'danger')
        return redirect(url_for('index'))

    search = request.form.get('search')


    filter_conditions = []

    if search:
        filter_conditions.append(User.username.ilike(f"%{search}%"))

    admin_users = User.query.filter(User.usertype == 'Admin', User.userid != current_user.userid)
    users = admin_users \
        .join(Profile, User.userid == Profile.userid, isouter=True) \
        .filter(*filter_conditions).all()

    return render_template('admin_user_list.html', users=users)

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


@app.route('/admin_edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_edit(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':

        user.username = request.form['username']
        user.password = request.form['password']
        user.email = request.form['email']

        try:
            db.session.commit()
            flash('Profile successfully updated', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'danger')

        return redirect(url_for('admin_dashboard'))

    return render_template('admin_edit.html', user=user)


@app.route('/send_message/<int:receiver_id>', methods=['GET', 'POST'])
@login_required
def send_message(receiver_id):
    try:
        receiver = User.query.filter_by(userid=receiver_id).one()
    except "NoResultFound":
        flash("User not found.", "danger")
        return redirect_to_dashboard()

    if request.method == 'POST':
        content = request.form.get('content').strip()
        if content:
            new_message = Message(senderid=current_user.userid, receiverid=receiver_id, content=content)
            db.session.add(new_message)
            db.session.commit()
            flash('Message sent successfully!', 'success')
            return redirect(url_for('view_conversation', other_user_id=receiver_id))
        else:
            flash('Message cannot be empty!', 'danger')

    return render_template('send_message.html', receiver=receiver, user_type=current_user.usertype)

def redirect_to_dashboard():
    if current_user.usertype == 'Admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.usertype == 'Company':
        return redirect(url_for('company_dashboard'))
    elif current_user.usertype == 'Athlete':
        return redirect(url_for('dashboard'))
    else:
        flash('Unknown user type', 'danger')
        return redirect(url_for('index'))

@app.route('/view_messages', methods=['GET'])
@login_required
def view_messages():
    current_user_id = current_user.get_id()

    search_query = request.args.get('search', '').strip()
    user_type_filter = request.args.get('user_type', '').capitalize()

    sent_messages = db.session.query(Message.receiverid).filter_by(senderid=current_user_id).subquery()
    received_messages = db.session.query(Message.senderid).filter_by(receiverid=current_user_id).subquery()

    users_query = User.query.filter(
        (User.userid.in_(sent_messages) | User.userid.in_(received_messages)) &
        (User.userid != current_user_id)
    ).join(Profile, User.profile)

    if search_query:
        users_query = users_query.filter(Profile.fullname.ilike(f'%{search_query}%'))

    if user_type_filter:
        users_query = users_query.filter(User.usertype == user_type_filter)

    users_with_details = users_query.distinct().all()

    return render_template('view_messages.html', users=users_with_details, search_query=search_query, user_type_filter=user_type_filter)


@app.route('/view_conversation/<int:other_user_id>')
@login_required
def view_conversation(other_user_id):
    current_user_id = current_user.get_id()
    other_user = User.query.get_or_404(other_user_id)


    sender = aliased(User)
    receiver = aliased(User)

    messages = db.session.query(
        Message,
        sender.username.label('sender_username'),
        receiver.username.label('receiver_username')
    ).join(sender, sender.userid == Message.senderid)\
     .join(receiver, receiver.userid == Message.receiverid)\
     .filter(
        ((Message.senderid == current_user_id) & (Message.receiverid == other_user_id)) |
        ((Message.senderid == other_user_id) & (Message.receiverid == current_user_id))
    ).order_by(Message.timestamp).all()

    return render_template('view_conversation.html', other_user=other_user, messages=messages)

def delete_conversation(current_user_id, other_user_id):
    Message.query.filter_by(senderid=current_user_id, receiverid=other_user_id).delete()
    Message.query.filter_by(senderid=other_user_id, receiverid=current_user_id).delete()
    db.session.commit()

@app.route('/delete_conversation/<int:other_user_id>', methods=['POST'])
@login_required
def delete_conversation_route(other_user_id):
    delete_conversation(current_user.userid, other_user_id)
    flash('Conversation deleted successfully!', 'success')
    return redirect(url_for('view_messages'))
@app.route('/go_back')
@login_required
def go_back():
    if current_user.usertype == 'Admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.usertype == 'Athlete':
        return redirect(url_for('dashboard'))
    elif current_user.usertype == 'Company':
        return redirect(url_for('company_dashboard'))
    flash('Unknown user type', 'error')
    return redirect(url_for('index'))


@app.route('/view_offers')
@login_required
def view_offers():
    athlete_profile = AthleteProfile.query.filter_by(profileid=current_user.profile.profileid).first()
    if not athlete_profile:
        flash('Athlete profile not found!', 'error')
        return redirect(url_for('dashboard'))

    relevant_offers_data = []
    relevant_offers = Offer.query.filter(
        Offer.athleteid == athlete_profile.athleteprofileid,
        or_(Offer.status == 'Pending',
            and_(Offer.status == 'Counter-offered', Offer.last_updated_by == 'Company'))
    ).all()

    for offer in relevant_offers:
        company_profile = CompanyProfile.query.filter_by(companyprofileid=offer.companyid).first()
        if company_profile:
            user_profile = Profile.query.filter_by(profileid=company_profile.profileid).first()
            relevant_offers_data.append((offer, company_profile, user_profile))

    return render_template('view_offers.html', offers=relevant_offers_data, title='Your Offers')

@app.route('/view_offer_history')
@login_required
def view_offer_history():
    athlete_profile = AthleteProfile.query.filter_by(profileid=current_user.profile.profileid).first()
    if not athlete_profile:
        flash('Athlete profile not found!', 'error')
        return redirect(url_for('dashboard'))

    non_pending_offers_data = []
    non_pending_offers = Offer.query.filter(
        Offer.athleteid == athlete_profile.athleteprofileid,
        Offer.status != 'Pending'
    ).all()

    for offer in non_pending_offers:
        company_profile = CompanyProfile.query.get(offer.companyid)
        if company_profile:
            user_profile = Profile.query.filter_by(profileid=company_profile.profileid).first()
            non_pending_offers_data.append((offer, company_profile, user_profile))

    return render_template('view_offer_history.html', offers=non_pending_offers_data)

@app.route('/accept_offer/<int:offer_id>', methods=['POST'])
@login_required
def accept_offer(offer_id):
    offer = Offer.query.get(offer_id)
    athlete_profile = AthleteProfile.query.filter_by(profileid=current_user.profile.profileid).first()

    if offer and offer.athleteid == athlete_profile.athleteprofileid:
        offer.status = 'Accepted'

        sponsorship = Sponsorship(companyid=offer.companyid, athleteid=offer.athleteid,
                                  details="Details of the sponsorship")
        db.session.add(sponsorship)

        db.session.commit()
        flash('Offer accepted successfully!', 'success')
    else:
        flash('Offer not found or unauthorized action', 'error')
    return redirect(url_for('view_offers'))



@app.route('/decline_offer/<int:offer_id>', methods=['POST'])
@login_required
def decline_offer(offer_id):
    offer = Offer.query.get(offer_id)
    athlete_profile = AthleteProfile.query.filter_by(profileid=current_user.profile.profileid).first()

    if offer and offer.athleteid == athlete_profile.athleteprofileid:
        offer.status = 'Declined'
        db.session.commit()
        flash('Offer declined successfully!', 'success')
    else:
        flash('Offer not found or unauthorized action', 'error')
    return redirect(url_for('view_offers'))


@app.route('/counter_offer/<int:offer_id>', methods=['POST'])
@login_required
def counter_offer(offer_id):
    offer = Offer.query.get(offer_id)
    athlete_profile = AthleteProfile.query.filter_by(profileid=current_user.profile.profileid).first()
    counter_details = request.form.get('counter_details')

    if offer and offer.athleteid == athlete_profile.athleteprofileid:
        offer.status = 'Counter-offered'
        offer.details = counter_details
        offer.last_updated_by = 'Athlete'
        db.session.commit()
        flash('Offer countered successfully!', 'success')
    else:
        flash('Offer not found or unauthorized action', 'error')
    return redirect(url_for('view_offers'))


@app.route('/company_offers')
@login_required
def company_offers():
    company_profile = CompanyProfile.query.filter_by(profileid=current_user.profile.profileid).first()
    if not company_profile:
        flash('Company profile not found!', 'error')
        return redirect(url_for('dashboard'))

    offers = db.session.query(
        Offer,
        AthleteProfile,
        Profile
    ).join(
        AthleteProfile, Offer.athleteid == AthleteProfile.athleteprofileid
    ).join(
        Profile, AthleteProfile.profileid == Profile.profileid
    ).filter(
        Offer.companyid == company_profile.companyprofileid,
        Offer.status.in_(['Pending', 'Counter-offered'])
    ).all()

    return render_template('company_offers.html', offers=offers)

@app.route('/company_offer_history')
@login_required
def company_offer_history():
    company_profile = CompanyProfile.query.filter_by(profileid=current_user.profile.profileid).first()
    if not company_profile:
        flash('Company profile not found!', 'error')
        return redirect(url_for('dashboard'))

    non_pending_offers_data = []
    non_pending_offers = Offer.query.filter(
        Offer.companyid == company_profile.companyprofileid,
        Offer.status.in_(['Accepted', 'Declined'])
    ).all()

    for offer in non_pending_offers:
        athlete_profile = AthleteProfile.query.filter_by(athleteprofileid=offer.athleteid).first()
        if athlete_profile:
            profile = Profile.query.filter_by(profileid=athlete_profile.profileid).first()
            non_pending_offers_data.append((offer, athlete_profile, profile))

    return render_template('company_offer_history.html', offers=non_pending_offers_data)


@app.route('/clear_offer_history', methods=['POST'])
@login_required
def clear_offer_history():
    if current_user.usertype == 'Company':
        company_profile = CompanyProfile.query.filter_by(profileid=current_user.profile.profileid).first()
        if company_profile:
            Offer.query.filter(
                Offer.companyid == company_profile.companyprofileid,
                Offer.status.in_(['Accepted', 'Declined'])
            ).delete()
            db.session.commit()
            flash('Offer history cleared successfully!', 'success')
        else:
            flash('Company profile not found!', 'error')
        return redirect(url_for('company_offer_history'))

    elif current_user.usertype == 'Athlete':
        athlete_profile = AthleteProfile.query.filter_by(profileid=current_user.profile.profileid).first()
        if athlete_profile:
            Offer.query.filter(
                Offer.athleteid == athlete_profile.athleteprofileid,
                Offer.status.in_(['Accepted', 'Declined'])
            ).delete()
            db.session.commit()
            flash('Offer history cleared successfully!', 'success')
        else:
            flash('Athlete profile not found!', 'error')
        return redirect(url_for('view_offer_history'))

    else:
        flash('Unauthorized action', 'error')
        return redirect(url_for('dashboard'))


@app.route('/company_offers/send/<int:athlete_id>', methods=['GET', 'POST'])
@login_required
def send_offer(athlete_id):
    if request.method == 'POST':
        details = request.form.get('details')
        company_profile = CompanyProfile.query.filter_by(profileid=current_user.profile.profileid).first()
        new_offer = Offer(companyid=company_profile.companyprofileid, athleteid=athlete_id, details=details, last_updated_by='Company')
        db.session.add(new_offer)
        db.session.commit()
        flash('Offer sent successfully!', 'success')
        return redirect(url_for('company_offers'))
    return render_template('company_send_offer.html')


@app.route('/company_offers/respond/<int:offer_id>', methods=['GET', 'POST'])
@login_required
def respond_offer(offer_id):
    offer = Offer.query.get_or_404(offer_id)
    athlete_profile = AthleteProfile.query.get(offer.athleteid)
    profile = Profile.query.get(athlete_profile.profileid) if athlete_profile else None

    if offer.status not in ['Counter-offered', 'Pending']:
        flash('This offer cannot be responded to.', 'error')
        return redirect(url_for('company_offers'))

    if offer.status == 'Pending' and offer.last_updated_by == 'Company':
        flash('Waiting for the athlete to respond.', 'info')
        return redirect(url_for('company_offers'))

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'accept':
            offer.status = 'Accepted'
            # Create a new sponsorship record when the company accepts the offer
            if current_user.usertype == 'Company':
                sponsorship = Sponsorship(companyid=offer.companyid, athleteid=offer.athleteid,
                                          details="Details of the sponsorship")
                db.session.add(sponsorship)
            db.session.commit()
            flash('Offer accepted successfully!', 'success')
        elif action == 'decline':
            offer.status = 'Declined'
            db.session.commit()
            flash('Offer declined successfully!', 'success')
        elif action == 'counter':
            details = request.form.get('details')
            if details:
                offer.details = details
                offer.status = 'Counter-offered'
                offer.last_updated_by = 'Company'
                db.session.commit()
                flash('Counter offer sent successfully!', 'success')
            else:
                flash('Please provide details for the counter offer.', 'error')
                return render_template('company_respond_offer.html', offer=offer, profile=profile)
        else:
            return redirect(url_for('company_offers'))

        if current_user.usertype == 'Athlete':
            return redirect(url_for('view_offers'))
        else:
            return redirect(url_for('company_offers'))

    return render_template('company_respond_offer.html', offer=offer, profile=profile)

@app.route('/company_offers/modify/<int:offer_id>', methods=['GET', 'POST'])
@login_required
def modify_offer(offer_id):
    offer = Offer.query.get_or_404(offer_id)

    company_profile = CompanyProfile.query.filter_by(profileid=current_user.profile.profileid).first()
    if offer.companyid != company_profile.companyprofileid:
        flash('Unauthorized action.', 'error')
        return redirect(url_for('company_offers'))

    if request.method == 'POST':
        offer.details = request.form.get('details')
        db.session.commit()
        flash('Offer updated successfully!', 'success')
        return redirect(url_for('company_offers'))

    return render_template('modify_offer.html', offer=offer)


@app.route('/company_offers/retract/<int:offer_id>', methods=['POST'])
@login_required
def retract_offer(offer_id):
    offer = Offer.query.get_or_404(offer_id)

    company_profile = CompanyProfile.query.filter_by(profileid=current_user.profile.profileid).first()
    if offer.companyid != company_profile.companyprofileid:
        flash('Unauthorized action.', 'error')
        return redirect(url_for('company_offers'))

    db.session.delete(offer)
    db.session.commit()
    flash('Offer retracted successfully!', 'success')
    return redirect(url_for('company_offers'))


@app.route('/view_sponsorees')
@login_required
def view_sponsorees():
    company_profile = CompanyProfile.query.filter_by(profileid=current_user.profile.profileid).first()
    if not company_profile:
        flash('Company profile not found!', 'error')
        return redirect(url_for('dashboard'))

    sponsorees = Sponsorship.query.filter_by(companyid=company_profile.companyprofileid).all()
    sponsoree_profiles = []
    for sponsoree in sponsorees:
        athlete_profile = AthleteProfile.query.get(sponsoree.athleteid)
        profile = Profile.query.get(athlete_profile.profileid)
        sponsoree_profiles.append(profile)

    return render_template('view_sponsorees.html', sponsoree_profiles=sponsoree_profiles)


@app.route('/athlete/sponsors')
@login_required
def view_sponsors():
    athlete_profile = AthleteProfile.query.filter_by(profileid=current_user.profile.profileid).first()
    if not athlete_profile:
        flash('Athlete profile not found.', 'danger')
        return redirect(url_for('dashboard'))

    sponsorships = Sponsorship.query.filter_by(athleteid=athlete_profile.athleteprofileid).all()
    sponsors = []
    for sponsorship in sponsorships:
        company = CompanyProfile.query.get(sponsorship.companyid)
        user = User.query.join(Profile).filter(Profile.profileid == company.profileid).first()
        sponsors.append((company, user))

    return render_template('view_sponsors.html', sponsors=sponsors)


@app.route('/remove_sponsorship/<int:athlete_id>', methods=['POST'])
@login_required
def remove_sponsorship(athlete_id):
    company_profile = CompanyProfile.query.filter_by(profileid=current_user.profile.profileid).first()
    if not company_profile:
        flash('Company profile not found!', 'error')
        return redirect(url_for('dashboard'))

    sponsorship_to_remove = Sponsorship.query.filter_by(companyid=company_profile.companyprofileid,
                                                        athleteid=athlete_id).first()

    if sponsorship_to_remove:
        db.session.delete(sponsorship_to_remove)
        db.session.commit()
        flash('Sponsorship removed successfully!', 'success')
    else:
        flash('Sponsorship not found!', 'error')

    return redirect(url_for('view_sponsorees'))

@app.route('/aboutus')
def about_us():
    return render_template('aboutus.html')

@app.route('/faqs')
def faqs():
    return render_template('faqs.html')

@app.route('/features')
def features():
    return render_template('features.html')

if __name__ == "__main__":
    app.run(debug=True)
