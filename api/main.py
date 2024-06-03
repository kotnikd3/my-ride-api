import json

from decouple import config
from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from api.infrastructure.authentication import KeycloakTokenValidator
from api.services.exceptions import InvalidTokenError, RefreshTokenExpiredError

app = Flask(__name__)
app.secret_key = config('SECRET_KEY')
app.config['SESSION_COOKIE_NAME'] = 'my-ride'
# For production
# app.config['SESSION_COOKIE_HTTPONLY'] = True
# app.config['SESSION_COOKIE_SECURE'] = True
# app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=2)


keycloak_validator = KeycloakTokenValidator()


def tokens_in_session_required(f):
    """Decorator to check if the token is in session and if it is
    valid and refresh it if necessary"""

    def decorated(*args, **kwargs):
        tokens = session.get('tokens', {})  # Default value = {}
        access_token = tokens.get('access_token')
        refresh_token = tokens.get('refresh_token')

        original_uri = request.path

        if not (access_token and refresh_token):
            return redirect(url_for('login', next=original_uri))

        try:
            if new_tokens := keycloak_validator.validate_tokens(
                access_token=access_token,
                refresh_token=refresh_token,
            ):
                session.clear()
                session['tokens'] = new_tokens
        except RefreshTokenExpiredError:
            session.clear()
            return redirect(url_for('login', next=original_uri))
        except InvalidTokenError as error:
            session.clear()
            abort(401, description=repr(error))

        return f(*args, **kwargs)

    return decorated


@app.route('/login')
def login():
    # If user has session in browser and in Keycloak, do not initiate the
    # login protocol again; instead just redirect him to index page
    if tokens := session.get('tokens'):
        access_token = tokens.get('access_token')
        if keycloak_validator.introspect(access_token=access_token):
            return redirect(url_for('index'))

    original_uri = request.args.get('next')
    redirect_uri = url_for(
        'authorize',
        _external=True,
        next=original_uri,
    )

    auth_url = keycloak_validator.auth_url(
        redirect_uri=redirect_uri,
        scope='openid email',
    )

    return redirect(auth_url)


@app.route('/authorize')
def authorize():
    # Get the authorization code from the callback URL
    code = request.args.get('code')

    original_uri = request.args.get('next')
    redirect_uri = url_for(
        'authorize',
        _external=True,
        next=original_uri,
    )

    # Exchange the authorization code for a token
    tokens = keycloak_validator.get_tokens(
        code=code,
        redirect_uri=redirect_uri,
    )

    session['tokens'] = tokens

    if original_uri:
        return redirect(original_uri)
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    if tokens := session.get('tokens'):
        refresh_token = tokens.get('refresh_token')
        keycloak_validator.logout(refresh_token=refresh_token)

    session.clear()

    return redirect(url_for('index'))


@app.route('/')
def index():
    if tokens := session.get('tokens'):
        tokens = json.dumps(tokens, sort_keys=True, indent=4)

    return render_template('index.html', data=tokens)


@app.route('/protected')
@tokens_in_session_required
def protected():
    return render_template('index.html', data='PROTECTED')
