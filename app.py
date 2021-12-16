
import datetime
from flask import Flask , request , render_template, url_for, redirect
from authlib.integrations.flask_client import OAuth
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, current_user, logout_user, login_required , UserMixin  , LoginManager
from flask_bcrypt import Bcrypt
import os
import random
import array

app = Flask(__name__)
oauth = OAuth(app)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:1234@localhost/Oauth"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
db = SQLAlchemy(app)


# take reference from medial login and registration article
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model , UserMixin):
    __tablename__ = 'User'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String() , unique=True, nullable=False)
    email = db.Column(db.String(), unique=True ,nullable=True )
    password = db.Column(db.String(128) ,  nullable=False)


    def __repr__(self):
        return f"id = {self.id} name = {self.name}"


app.config['SECRET_KEY'] = "THIS SHOULD BE SECRET"
app.config['GOOGLE_CLIENT_ID'] = "1010198604289-s8e96koi209jdk3ih8jkjb9h4kb90981.apps.googleusercontent.com"
app.config['GOOGLE_CLIENT_SECRET'] = "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"
app.config['GITHUB_CLIENT_ID'] = "b339e7a17517b6470a70"
app.config['GITHUB_CLIENT_SECRET'] = "64b8f2b5e0b3eee7a3165af2725095023525afe5"

google = oauth.register(
    name = 'google',
    client_id = app.config["GOOGLE_CLIENT_ID"],
    client_secret = app.config["GOOGLE_CLIENT_SECRET"],
    access_token_url = 'https://accounts.google.com/o/oauth2/token',
    access_token_params = None,
    authorize_url = 'https://accounts.google.com/o/oauth2/auth',
    authorize_params = None,
    api_base_url = 'https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint = 'https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs = {'scope': 'openid email profile'},
)

github = oauth.register (
  name = 'github',
    client_id = app.config["GITHUB_CLIENT_ID"],
    client_secret = app.config["GITHUB_CLIENT_SECRET"],
    access_token_url = 'https://github.com/login/oauth/access_token',
    access_token_params = None,
    authorize_url = 'https://github.com/login/oauth/authorize',
    authorize_params = None,
    api_base_url = 'https://api.github.com/',
    client_kwargs = {'scope': 'user:email'},
)


# routing

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        print(email , name)

        if User.query.filter_by(name=name).first():
            return 'Username already in use.'
        if User.query.filter_by(email=email).first():
            return 'email already in use.'
        if name is None:
            return 'enter name'
        if email is None:
            return 'enter email'
        if password is None:
            return 'enter password'

        hashed_password =  bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(name = name,
                    email = email,
                    password = hashed_password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        return redirect("/profile")
    else:
        return render_template("signup.html")
# Google login route
@app.route('/login/google')
def google_login():
    google = oauth.create_client('google')
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


# Google authorize route
@app.route('/login/google/authorize')
def google_authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('userinfo' ,  token=token ).json()
    print(f"\n{resp}\n")
    if User.query.filter_by(name=resp["name"]).first():
            return 'Username already in use.'
    
    if User.query.filter_by(email=resp["email"]).first():
            return 'Email already in use.'
    else:
        
        # maximum length of password needed
        # this can be changed to suit your password length
        MAX_LEN = 12
        
        # declare arrays of the character that we need in out password
        # Represented as chars to enable easy string concatenation
        DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']  
        LOCASE_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 
                            'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
                            'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                            'z']
        
        UPCASE_CHARACTERS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 
                            'I', 'J', 'K', 'M', 'N', 'O', 'p', 'Q',
                            'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                            'Z']
        
        SYMBOLS = ['@', '#', '$', '%', '=', ':', '?', '.', '/', '|', '~', '>', 
                '*', '(', ')', '<']
        
        # combines all the character arrays above to form one array
        COMBINED_LIST = DIGITS + UPCASE_CHARACTERS + LOCASE_CHARACTERS + SYMBOLS
        
        # randomly select at least one character from each character set above
        rand_digit = random.choice(DIGITS)
        rand_upper = random.choice(UPCASE_CHARACTERS)
        rand_lower = random.choice(LOCASE_CHARACTERS)
        rand_symbol = random.choice(SYMBOLS)
        
        # combine the character randomly selected above
        # at this stage, the password contains only 4 characters but 
        # we want a 12-character password
        temp_pass = rand_digit + rand_upper + rand_lower + rand_symbol
        
        
        # now that we are sure we have at least one character from each
        # set of characters, we fill the rest of
        # the password length by selecting randomly from the combined 
        # list of character above.
        for x in range(MAX_LEN - 4):
            temp_pass = temp_pass + random.choice(COMBINED_LIST)
        
            # convert temporary password into array and shuffle to 
            # prevent it from having a consistent pattern
            # where the beginning of the password is predictable
            temp_pass_list = array.array('u', temp_pass)
            random.shuffle(temp_pass_list)
        
        # traverse the temporary password array and append the chars
        # to form the password
        password = ""
        for x in temp_pass_list:
                password = password + x
                
        # print out password
        print(password)
        user = User(name = resp["name"],
                    email = resp["email"],
                    password = password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
    return redirect('/profile')


# Github login route
@app.route('/login/github')
def github_login():
    github = oauth.create_client('github')
    redirect_uri = url_for('github_authorize', _external=True)
    return github.authorize_redirect(redirect_uri)


# Github authorize route
@app.route('/login/github/authorize')
def github_authorize():
    github = oauth.create_client('github')
    token = github.authorize_access_token()
    resp = github.get('user' ,  token=token).json()
    print({resp["login"]} , "\n")
    if User.query.filter_by(name=resp["login"]).first():
            return 'Username already in use.'
    else:
        
        # maximum length of password needed
        # this can be changed to suit your password length
        MAX_LEN = 12
        
        # declare arrays of the character that we need in out password
        # Represented as chars to enable easy string concatenation
        DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']  
        LOCASE_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 
                            'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
                            'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                            'z']
        
        UPCASE_CHARACTERS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 
                            'I', 'J', 'K', 'M', 'N', 'O', 'p', 'Q',
                            'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                            'Z']
        
        SYMBOLS = ['@', '#', '$', '%', '=', ':', '?', '.', '/', '|', '~', '>', 
                '*', '(', ')', '<']
        
        # combines all the character arrays above to form one array
        COMBINED_LIST = DIGITS + UPCASE_CHARACTERS + LOCASE_CHARACTERS + SYMBOLS
        
        # randomly select at least one character from each character set above
        rand_digit = random.choice(DIGITS)
        rand_upper = random.choice(UPCASE_CHARACTERS)
        rand_lower = random.choice(LOCASE_CHARACTERS)
        rand_symbol = random.choice(SYMBOLS)
        
        # combine the character randomly selected above
        # at this stage, the password contains only 4 characters but 
        # we want a 12-character password
        temp_pass = rand_digit + rand_upper + rand_lower + rand_symbol
        
        
        # now that we are sure we have at least one character from each
        # set of characters, we fill the rest of
        # the password length by selecting randomly from the combined 
        # list of character above.
        for x in range(MAX_LEN - 4):
            temp_pass = temp_pass + random.choice(COMBINED_LIST)
        
            # convert temporary password into array and shuffle to 
            # prevent it from having a consistent pattern
            # where the beginning of the password is predictable
            temp_pass_list = array.array('u', temp_pass)
            random.shuffle(temp_pass_list)
        
        # traverse the temporary password array and append the chars
        # to form the password
        password = ""
        for x in temp_pass_list:
                password = password + x
                
        # print out password
        print(password)
        user = User(name = resp["login"],
                    password = password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
    return redirect('/profile')


@app.route('/profile')
def profile():
    return render_template('profile.html')



if __name__ == '__main__':
    app.run(debug=True)