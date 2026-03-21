#fastapi
from fastapi import Depends, FastAPI, HTTPException, status,Cookie, Request, Response 
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import FastAPI,UploadFile
from fastapi.responses import RedirectResponse,HTMLResponse,FileResponse,JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from typing import Union
import asyncio 
from datetime import datetime, timedelta, timezone
from typing import Annotated
from api_utils.logger import logger 

#Encryption
from cryptography.fernet import Fernet

#pydantic
from pydantic import BaseModel

#json web tokens 
import jwt

#Okta Oauth 
from authlib.integrations.starlette_client import OAuth


#Starlette 
from starlette.middleware.sessions import SessionMiddleware
from starlette.config import Config


#YNAB 
from ynab import ApiClient, Configuration
from ynab.api.transactions_api import TransactionsApi
from ynab.models.new_transaction import NewTransaction
from ynab.models.post_transactions_wrapper import PostTransactionsWrapper
from api_utils.ynab import filter_mobilebanken_transactions, YNABAPI


#Transcribing
from api_utils.adnepos import Transcriber


#Gemini 
from google import genai
from google.genai import types


#general 
import os
import requests
import json 
import base64
import mimetypes




#Own defined utilss 
from api_utils.files import HandleFiles 


UPLOAD_DIR = "./uploads"

SECRET_KEY_JWT = "jwt_key" 
MASTER_KEY = "master_key"
ALGORITHM = "HS256"


#Okta credentials
if os.getenv("ENVIRONMENT") == "dev":
    AUTH0_DOMAIN = os.getenv("AUTH_DOMAIN")
    AUTH0_CLIENT_ID = os.getenv("AUTH_CLIENT_ID")
    AUTH0_CLIENT_SECRET = os.getenv("AUTH_CLIENT_SECRET")
    print(f"environment is dev")
    print(f"{AUTH0_DOMAIN=}")
    JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
    ISSUER = f"https://{AUTH0_DOMAIN}/" 
    AUTH0_AUDIENCE = os.getenv("AUTH_AUDIENCE") 

    BSU_ACCOUNT_NR = os.getenv("BSU_ACCOUNT_NR")
    SPAREKONTO_18_23_ACCOUNT_NR = os.getenv("SPAREKONTO_18_23_ACCOUNT_NR")
    CHECKING_ACCOUNT_NR = os.getenv("CHECKING_ACCOUNT_NR")

    ##YNAB: 
    YNAB_TOKEN = os.getenv("YNAB_PAC")
else: 
    AUTH0_DOMAIN = os.getenv("AUTH-DOMAIN")
    AUTH0_CLIENT_ID = os.getenv("AUTH-CLIENT-ID")
    AUTH0_CLIENT_SECRET = os.getenv("AUTH-CLIENT-SECRET")
    print(f"environment is prod")
    JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
    ISSUER = f"https://{AUTH0_DOMAIN}/" 
    AUTH0_AUDIENCE = os.getenv("AUTH-AUDIENCE") 
    YNAB_TOKEN = os.getenv("YNAB-PAC")



#FastAPI credentials
API_SECRET_KEY = os.getenv("API-SECRET-KEY")

jwks = requests.get(JWKS_URL).json()





app = FastAPI()


origins = [
    "http://localhost:8000", 
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],         
    allow_credentials=True,
    allow_methods=["*"],          
    allow_headers=["*"],           
)

templates = Jinja2Templates(directory="static")
mimetypes.add_type("application/wasm", ".wasm")
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




#this would potentially only be of programmatic access where you put the token in the json payload, preferrably encrypted 
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")



class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    avatar: str | None = None  
    user_id: str | None = None  
    disabled: bool | None = None

class FileObject(BaseModel):
    filename: str 

class TranscribeRequest(BaseModel):
    filenames: list[str] 
    #transcribe_all_images: bool


####CLIENTS 

gemini_client = genai.Client() #Needs gemini api key in the env 



###### Need a place to initalise all classes i need 
ynab_instance = YNABAPI(YNAB_PAC=YNAB_TOKEN)
transcriber_instance = Transcriber(client=gemini_client)
#####










@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):

    logger.info(f"Global Error Handler: {exc.status_code=}, {exc.detail=} ")

    if exc.status_code == 401: 
        return RedirectResponse(url="/login")

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "code": exc.status_code,
            "message": exc.detail,
            "path": request.url.path
        },
    )


async def get_user_and_validate_session(request: Request):
    
    user = request.session.get("user")

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = user.get("access_token")
    
    id_token = user.get("id_token")

    if id_token:

        headers = jwt.get_unverified_header(id_token)
        kid = headers.get("kid")
    else:
        raise HTTPException(
                status_code= status.HTTP_401_UNAUTHORIZED,
                detail = "Could not find KID for verification of Access token")

    
    for key in jwks["keys"]:
        kid_in_key = key["kid"]
        logger.info(f" kid in keys: {kid_in_key}")
        if key["kid"] == kid:
            signing_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))

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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT decoding error"
        )
        



#this might be useful still 
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


#this needs some work 
async def get_current_active_user(current_user: User = Depends(get_user_and_validate_session)) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user






















#General stuff that needs to be available across many endpoints in the API 
@app.post("/upload")
async def upload_file(file: UploadFile,user: User = Depends(get_user_and_validate_session) ):

    os.makedirs(UPLOAD_DIR,exist_ok=True)

    file_path = os.path.join(UPLOAD_DIR, file.filename)

    logger.info(f"Saving file to path on server: {file_path=}")

    try:
        size = await HandleFiles.write_file(file=file, file_path=file_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload/save file: {e}")


    logger.info(f"File Saved")



    return {
        "status_code": 200,
        "filename": file.filename,
        "content_type": file.content_type,
        "size": size,
    }


@app.post("/adnepos/transcribe")
async def transcribe_image(transcribe_request: TranscribeRequest,  user: User = Depends(get_user_and_validate_session)):
    MAX_FILES = 20
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


    if not transcribe_request.filenames:
        raise HTTPException(status_code=400, detail="No filenames provided.")

    for filename in transcribe_request.filenames:
        if ".." in filename or filename.startswith("/"):
            raise HTTPException(status_code=400, detail=f"Invalid filename: {filename}")

    if len(transcribe_request.filenames) > MAX_FILES:
        raise HTTPException(status_code=400, detail=f"Too many files. Maximum {MAX_FILES} allowed.")


    
    images = []
    for filename in transcribe_request.filenames:
        file_path = os.path.join(UPLOAD_DIR, filename)
        if not os.path.isfile(file_path):
            raise HTTPException(status_code=404, detail=f"File not found: {filename}")

        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail=f"File too large: {filename}")
        images.append((file_path, filename))
    
    coroutines = []
    for image_path, image_filename in images:
        image_bytes = await HandleFiles.read_file(file_path=image_path, mode='rb')
        transcribe_result = transcriber_instance.process_image(image_bytes, image_filename)
        coroutines.append(transcribe_result)

    result = await asyncio.gather(*coroutines)


    return {"results": result} 


@app.post("/ynab/export")
async def export_ynab(export_request: FileObject, user: User = Depends(get_user_and_validate_session)):

    file_path = os.path.join(UPLOAD_DIR, export_request.filename)

    arrow = await HandleFiles.read_csv(file_path)

    accounts = [SPAREKONTO_18_23_ACCOUNT_NR, CHECKING_ACCOUNT_NR,BSU_ACCOUNT_NR ]

    metadata = {}

    for account in accounts: 
        
        transaction_table, metadata = await filter_mobilebanken_transactions(arrow=arrow,from_account=account,to_account=account)
        transactions = await ynab_instance.create_transactions(transaction_table)
        api_response = await ynab_instance.import_transactions(transactions)
        metadata[account] = api_response


    return {
        "status_code": 200, 
        "metadata" : metadata
    }
        


@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_user_and_validate_session)):
    return current_user







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

@app.get("/ynab/homepage")
async def get_ynab_homepage():
    return FileResponse("static/ynab.html")

@app.get("/adnepos")
async def adnepos(user: User = Depends(get_user_and_validate_session)):
    return FileResponse("static/adnepos.html")

@app.get("/report")
async def report(user: User = Depends(get_user_and_validate_session)):
    return FileResponse("static/report.html")

@app.get("/cv")
async def cv():
    return FileResponse("static/cv.html")

@app.get("/cv/game")
async def cv():
    return FileResponse("static/rust/cv_game/index.html")

@app.get("/cv_game_redirect")
def redirect_me():
    return RedirectResponse(url="/cv")

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
