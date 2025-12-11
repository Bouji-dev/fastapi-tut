
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta, timezone
from typing import Annotated

# Hashing and JWT
from jose import JWTError, jwt
from passlib.context import CryptContext

#------------
# Constants and Configs
#------------

app = FastAPI()

# JWT Config
SECRET_KEY = 'Your-super-secret-key-replace-me' 
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Hashing Config
# Using Bcrypt for hashing password securely
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token') # token extractor from Header


#-----------------
# Simple Database
#-----------------
# usernaem and password is created already
# we don't use raw password (PREDEFINED_PASSWORD), instead of we use (PREDEFINED_HASHED_PASSWORD)
PREDEFINED_USERNAME = 'admin_user'
# hashing 'secret_password' by bcrypt
PREDEFINED_HASHED_PASSWORD = pwd_context.hash('secret_password')

#--------------
# Utility Functions
#--------------

def verify_password(plain_password: str, hashed_password:str) -> bool:
    '''
    it's check that raw password and hashed password are compliance
    '''
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    '''
    creating token (JWT , JWS)
    '''
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({'exp':expire, 'sub': data['username']})
    # The token is signed here
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_from_db(username:str) -> dict | None:
    '''
    Simulating user retrieval from database
    '''
    if username == PREDEFINED_USERNAME:
        return{'username':PREDEFINED_USERNAME, 'hashed_password':PREDEFINED_HASHED_PASSWORD}
    return None

def authenticate_user(username: str, password: str) -> dict | None:
    '''
    user authentication by checking the username and hashed password
    '''
    user = get_user_from_db(username)
    if not user:
        return None
    if not verify_password(password, user['hashed_password']):
        return None
    return user

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    '''
    Dependency function for extracting, validating, and returning the user verification
    '''
    credentials_exception = HTTPException(
        status_code= status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={'WWW-Authenticate': 'Bearer'},
    )
    try:
        # Decryption and validation of token signature (JWS)
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Extract username from claim 'sub'
        username: str = payload.get('sub')
        if username is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    user = get_user_from_db(username)    
    if user is None:
        raise credentials_exception
    
    # If authentication is successful
    return user

#---------------
# Endpoints
#---------------

# 1. Root without authentication
@app.get('/')
def read_root():
    return {'message': 'This is the main root - Unprotected'}

# 2. Endpoint for recieve token (REST Auth)
@app.post('/token')
def login_for_access_token(from_data: Annotated[OAuth2PasswordRequestForm,Depends()]):
    '''
    Get username and password via POST and return authentication token (JWT)
    '''
    user = authenticate_user(from_data.username, from_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    # creating JWT token
    access_token = create_access_token(data={'username': user['username']})
    
    # Return the token in the OAuth2 standard
    return {'access_token': access_token, 'token_type':'bearer'}

#3. Token-protected endpoint
@app.get('/protected/data')
def read_protected_data(current_user: Annotated[dict,Depends(get_current_user)]):
    '''
    This endpoint can only be used if authenticated with the corresponding token.
    '''
    username = current_user['username']
    return{
        'message': f'Secret data for authenticated user:{username}',
        'secret': 'API_KEY_12345',
        'auth_method': 'JWT'
    }

# 4. #4. Another endpoint that requires authentication
@app.get('/admin/status')
def get_admin_status(current_user: Annotated[dict, Depends(get_current_user)]):
    username = current_user['username']
    return{'status': 'System Operational', 'user_checked_by': username}

