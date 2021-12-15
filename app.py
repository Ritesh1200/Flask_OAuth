
from flask import Flask , request , render_template, url_for, redirect
from authlib.integrations.flask_client import OAuth

# from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
oauth = OAuth(app)

# app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:1234@localhost/flask_rest"
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db = SQLAlchemy(app)
# api = Api(app)

# class Book(db.Model):
#     __tablename__ = 'books'

#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String())
#     author = db.Column(db.String())
#     created = db.Column(db.DateTime, default=datetime.datetime.utcnow)

#     def __init__(self, name, author):
#         self.name = name
#         self.author = author

#     def __repr__(self):
#         return f"id = {self.id} name = {self.name}"


app.config['SECRET_KEY'] = "THIS SHOULD BE SECRET"
app.config['GOOGLE_CLIENT_ID'] = "1010198604289-s8e96koi209jdk3ih8jkjb9h4kb90981.apps.googleusercontent.com"
app.config['GOOGLE_CLIENT_SECRET'] = "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"

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


# routing

@app.route('/')
def index():
    return render_template('index.html')

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
    resp = google.get('userinfo').json()
    print(f"\n{resp}\n")
    return redirect('/profile')

@app.route('/profile')
def profile():
    return render_template('profile.html')





if __name__ == '__main__':
    app.run(debug=True)