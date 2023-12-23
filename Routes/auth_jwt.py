from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta

router = APIRouter()    
auth2 = OAuth2PasswordBearer(tokenUrl="login")
ALGORITHM = "HS256"
ACCESS_TOKEN_DURATION = 2
SECRET = "a0955eeb684afc35aa804ab4cce77ba6a23665355a183d1a36c546e3ae943c7e"
crypt = CryptContext(schemes=["bcrypt"])

class User(BaseModel):
    id : int
    username: str
    email : str
    disable : bool


class UserDB(User):    
    password: str


users_db = {
    "Carlos" : {
        "id" : 1,
        "username" : "Carlos",
        "email" : "carlos@gmail.com",
        "disable" : False,
        "password" : "$2a$12$J112L.Sq8FDoXLnB.vjOCulpdOxNuR3c8.QAqf7pVX41chxxN0pCG"
    },
    "Eduardo" : {
        "id" : 2,
        "username" : "Eduardo",
        "email" : "edu.vargas@gmail.com",
        "disable" : True,
        "password" : "$2a$12$o3iWYJX0bkLl33Wxc0cr3OSEnk/2eIwulAS05IwaWOLiz0XEa9ASW"
    }
}

def search_user (username : str):
    if username in users_db:
        return User(**users_db[username])

def search_user_db (username : str):
    if username in users_db: 
        return UserDB(**users_db[username])
    

    
async def auth_user(token : str = Depends(auth2)):

    #Excepcion por si el token no coicide con el usuario
    exception = HTTPException(status.HTTP_401_UNAUTHORIZED, 
                            detail="La autentiaccion ha sido invalida", 
                            headers={"WWW-Authenticate" : "Bearer"})

    try:
        username = jwt.decode(token, SECRET, algorithms=[ALGORITHM]).get("sub")
        if username is None:
            raise exception

    except JWTError:
        raise exception

    return search_user(username)      

async def current_user(user : User = Depends(auth_user)):
    if user.disable:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="El usuario esta inactivo")
    
    return user

@router.post("/login")
async def login(form : OAuth2PasswordRequestForm = Depends()):
    user_db = users_db.get(form.username)
    
    #Si el usuario no exite
    if not user_db:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="El usuario no es correcto")
    
    #Si la contraseña no es igual al del formulario
    user = search_user_db(form.username)

    if not crypt.verify(form.password, user.password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="La contraseña no es correcta")
    
    #Generando el token de acceso
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_DURATION)
    
    access_token = {
        "sub" : user.username,
        "exp" : expire
    }    

    #Retorna el usurio, en un futuro buscare que retorne un token encriptado
    return {"access_token" : jwt.encode(access_token, SECRET, algorithm=ALGORITHM), "token_type" : "bearer"}

@router.get("/users/me")
async def me(user : User = Depends(current_user)):
    return user