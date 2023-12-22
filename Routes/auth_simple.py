from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm


router = APIRouter()
auth2 = OAuth2PasswordBearer(tokenUrl="login")

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
        "password" : "1234567"
    },
    "Eduardo" : {
        "id" : 2,
        "username" : "Eduardo",
        "email" : "edu.vargas@gmail.com",
        "disable" : True,
        "password" : "0987654"
    }
}

def search_user (username : str):
    if username in users_db:
        return User(**users_db[username])

def search_user_db (username : str):
    if username in users_db: 
        return UserDB(**users_db[username])
    
async def current_user(token : str = Depends(auth2)):
    user = search_user(token)
    #si el token no coicide con el usuario
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 
                            detail="La autentiaccion ha sido invalida", 
                            headers={"WWW-Authenticate" : "Bearer"})
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
    if not form.password == user.password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="La contraseña no es correcta")
    
    #Retorna el usurio, en un futuro buscare que retorne un token encriptado
    return {"access_token" : user.username, "token_type" : "bearer"}

@router.get("/users/me")
async def me(user : User = Depends(current_user)):
    return user