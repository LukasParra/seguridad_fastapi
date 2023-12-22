from fastapi import FastAPI
from Routes import auth_simple

app  = FastAPI()
app.include_router(auth_simple.router)

