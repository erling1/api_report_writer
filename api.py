#fastapi
from fastapi import Depends, FastAPI, HTTPException, status,Cookie, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import FastAPI


from typing import Union
import asyncio 
from datetime import datetime, timedelta, timezone
from typing import Annotated
import logging

#pydantic
from pydantic import BaseModel

#json web tokens 
import jwt
from jwt.exceptions import InvalidTokenError

SECRET_KEY = "your-very-secret-key-replace-me" 
ALGORITHM = "HS256"

app = FastAPI()

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
    disabled: bool | None = None

class UserInDB(User):
    hashed_password: str


fake_db = {
    'johannes': {
        'username' : 'johannes',
        'email' : 'johannes@gmail',
        'hashed_password' : 'hashed' + 'test'

    },
    
}

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

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    logger.info(f"Successfully created JWT for user: {data.get('sub')}")

    return encoded_jwt

async def get_current_user(token: str = Depends(get_token_from_cookie)) -> User:
    """Decodes and validates the JWT, returning the user object."""

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        username: str = payload.get("sub")

        if username is None:
            raise credentials_exception
            
        user_dict = fake_db.get(username)
        if user_dict is None:
             raise credentials_exception
             
        user = User(**user_dict) 

    except JWTError:
        raise credentials_exception
        
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user







@app.get("/")
async def read_root():
    return {"Hello": "World"}



@app.post("/token")
async def login(response: Response,form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):

    user_dict = fake_db.get(form_data.username)

    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)

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
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/items/{item_id}")
async def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}
