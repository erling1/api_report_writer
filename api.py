#fastapi
from fastapi import Depends, FastAPI, HTTPException, status,Cookie, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import FastAPI
from fastapi.responses import RedirectResponse,HTMLResponse,FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from typing import Union
import asyncio 
from datetime import datetime, timedelta, timezone
from typing import Annotated
import logging

#Encryption
from cryptography.fernet import Fernet

#pydantic
from pydantic import BaseModel

#json web tokens 
import jwt
from jwt.exceptions import InvalidTokenError

#Okta Oauth 
from authlib.integrations.starlette_client import OAuth


#Starlette 
from starlette.middleware.sessions import SessionMiddleware
from starlette.config import Config

#general 
import os
import requests
import json 
import base64





SECRET_KEY_JWT = "jwt_key" 
MASTER_KEY = "master_key"
ALGORITHM = "HS256"

#Okta credentials
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
ISSUER = f"https://{AUTH0_DOMAIN}/" 
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE") 


#FastAPI credentials
API_SECRET_KEY = os.getenv("API_SECRET_KEY")

jwks = requests.get(JWKS_URL).json()



app = FastAPI()

templates = Jinja2Templates(directory="static")

app.mount("/static", StaticFiles(directory="static", html=True), name="static")

app.add_middleware(SessionMiddleware, secret_key=API_SECRET_KEY)

#Set up config for Okta OAuth, credentials are fetched automaticaly from env 
config = Config()
oauth = OAuth(config)

oauth.register(
    name='auth0',  
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    server_metadata_url=f"https://{AUTH0_DOMAIN}/.well-known/openid-configuration",
    client_kwargs={
        'scope': 'openid profile email'
    }
)


logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

#this would potentially only be of programmatic access where you put the token in the json payload, preferrably encrypted 
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")



class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    avatar: str | None = None  # Added to match your dict
    user_id: str | None = None  # Added to match your dict
    disabled: bool | None = None

class UserInDB(User):
    hashed_password: str


fake_db = {
    'erling': {
        'username' : 'erling',
        'email' : 'johannes@gmail',
        'hashed_password' : 'hashed' + 'test'

    },
    
}




#I want one more way to access my api, mostly to practice setting up endpoints using various secure methods

def generate_master_key_remote_api_call():

    master_key = Fernet.generate_key()

    from dotenv import set_key
    set_key(".env", "master_key", master_key)


def generate_token_remote_api_call(username:str, expire_delta: int):

    master_key = os.getenv('master_key')

    print(master_key)

    expire = datetime.now(timezone.utc) + timedelta(minutes=expire_delta)

    payload = {
        'user': username,
        'expire': expire.timestamp()
    }
    

    payload_bytes = json.dumps(payload).encode('utf-8')

    print(payload_bytes)

    encrypted_token = Fernet(master_key).encrypt(payload_bytes)

    print(f"jwe token : {encrypted_token}")

    return encrypted_token





async def get_token_from_cookie(request: Request) -> str:
    """Retrieves the access token from the cookie."""
    access_token = request.cookies.get("access_token")
    if access_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated (Missing Cookie)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return access_token

async def fake_hash_password(password: str) -> str: 
    return 'hashed' + password

async def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:

    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY_JWT, algorithm=ALGORITHM)

    logger.info(f"Successfully created JWT for user: {data.get('sub')}")

    return encoded_jwt

async def get_current_user_and_validate_token(token: str = Depends(get_token_from_cookie)) -> User:
    """Decodes and validates the JWT, returning the user object."""

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY_JWT, algorithms=[ALGORITHM])
        
        username: str = payload.get("sub")

        if username is None:
            raise credentials_exception
            
        user_dict = fake_db.get(username)
        if user_dict is None:
             raise credentials_exception
             
        user = User(**user_dict) 

        logger.info(f"User: {user.username}")

    except JWTError:
        raise credentials_exception
        
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user_and_validate_token)) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def get_user_and_validate_session(request: Request):
    
    user = request.session.get("user")

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = user.get("access_token")
    
    logger.info(f"token: {token}")
    
    id_token = user.get("id_token")

    if id_token:

        headers = jwt.get_unverified_header(id_token)
        kid = headers.get("kid")
    else:
        raise Exception("Could not find kid for verification of access_token")

    logger.info(f"checking kid : {kid}")
    
    for key in jwks["keys"]:
        kid_in_key = key["kid"]
        logger.info(f" kid in keys: {kid_in_key}")
        if key["kid"] == kid:
            signing_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
    logger.info(f"checking user content: {user}")

    userinfo = user.get("userinfo", {})

    person_data = {
    "username": userinfo.get("nickname"),
    "full_name": userinfo.get("name"),
    "email": userinfo.get("email"),
    "avatar": userinfo.get("picture"),
    "user_id": userinfo.get("sub")  # The unique Auth0 ID
}
    header = jwt.get_unverified_header(token)
    algo = header.get("alg")
    logger.info(f"issuer: {ISSUER}") 



    try: 

        payload = jwt.decode(
            id_token,
            signing_key,
            algorithms=["RS256"],
            audience=AUTH0_AUDIENCE,
            issuer=ISSUER
    )
        
        current_user = User(**person_data)

        return current_user

    except Exception as e:
        logger.info(f"JWT decoding error, Exception: {e}")
        return None 




@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    user = request.session.get("user")
    
    pretty_user = json.dumps(user, indent=4) if user else None
    
    return templates.TemplateResponse(
        "home.html", 
        {
            "request": request, 
            "session": user, 
            "pretty": pretty_user
        }
    )


@app.get("/login")
async def login(request: Request):
    redirect_uri = request.url_for("callback")
    return await oauth.auth0.authorize_redirect(request, redirect_uri)

@app.get("/callback")
async def callback(request: Request):
    token = await oauth.auth0.authorize_access_token(request)
    request.session["user"] = token
    return RedirectResponse(url="/")


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/")

@app.get("/test")
async def test_api(user: User = Depends(get_user_and_validate_session)):
    
    logger.info(f"Checking User: {user}")

    return user







@app.post("/token")
async def login(response: Response,form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):

    logger.info(f"Checking response in /token endpoint: {response.body}, also checking form_data: {form_data.password} {form_data.username} ")

    user_dict = fake_db.get(form_data.username)

    logger.info(f"user_dict :{user_dict}")

    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    user = UserInDB(**user_dict)
    logger.info(f"User (UserInDB): {user}")
    hashed_password = await fake_hash_password(form_data.password)
    logger.info(f"hashed_password: {hashed_password}")
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect password")

    access_token = await create_access_token(data={"sub": user.username})


    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,     # JS cannot access it — prevents XSS token theft
        secure=False,      # Set to True if using HTTPS
        samesite="strict", # Prevent CSRF unless using SameSite=None
        max_age=3600       # 1 hour (optional)
    )

    logger.info(f"User {form_data.username} successfully logged in and received cookie.")

    return {"access_token":access_token, "token_type": "bearer"}





@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user_and_validate_token)):
    return current_user


@app.get("/items/{item_id}")
async def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}
