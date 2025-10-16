from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets       # for sensitive to time


app = FastAPI()
security = HTTPBasic()


PREDEFINED_USERNAME = 'admin_user'
PREDEFINED_PASSWORD = 'secret_password'

#-------------
# Authenticator
#-------------

def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    '''
    check validation of username and password  

    '''
    correct_username = secrets.compare_digest(credentials.username , PREDEFINED_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, PREDEFINED_PASSWORD)

    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail= ' User information is invalid',
            headers= {'WWW-Authenticate': 'Basic'}
        )
    return credentials.username



# main root whitout authentication       
@app.get('/')
def read_root():
    return {'message': 'This is the main root'}


#------------
# protected root
#------------

@app.get('/protected/data')
def read_protected_data(username:str=Depends(authenticate_user)):
    '''
    This root is available for Authenticated users only
    '''
    return {'message': f'secret data for user{username}', 'secret': 'API_KEY_12345'}