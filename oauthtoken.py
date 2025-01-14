'''
Use OAuth2 authentication
'''


from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import joblib
from typing import Optional
import jwt
import uvicorn

app = FastAPI()
model = joblib.load("model.pkl")

users_db = {
    "admin": {"username": "admin", "password": "password", "role": "admin"},
    "user": {"username": "user", "password": "password", "role": "user"}
}
SECRET_KEY = "your_secret_key"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
class User(BaseModel):
    username: str
    password: str
    role: str 
    

class PredictionRequest(BaseModel):
    sepal_length: float
    sepal_width: float
    petal_length: float
    petal_width: float
    

def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user_data = users_db.get(username)
        if user_data is None:
            raise HTTPException(
                status_code=401,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return User(username=user_data["username"], password="", role=user_data["role"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def role_checker(required_role: str):
    def role_dependency(current_user: User = Depends(get_current_user)):
        if current_user.role != required_role:
            raise HTTPException(
                status_code=403,
                detail="Operation not permitted",
            )
        return current_user
    return role_dependency
def authenticate_user(username: str, password: str) -> Optional[User]:
    user_data = users_db.get(username) 
    if user_data and user_data["password"] == password:
        return User(username=user_data["username"], password=user_data["password"], role=user_data["role"])
    return None
    
def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm="HS256")

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token({"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/predict")
async def predict(request: PredictionRequest, 
                  token: str = Depends(oauth2_scheme), 
                  current_user: User = Depends(role_checker("admin"))):
    try:
        # Decode JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        # Convert request data to a format suitable for the model
        data = [
            [
                request.sepal_length,
                request.sepal_width,
                request.petal_length,
                request.petal_width,
            ]
        ]
        # Make a prediction
        prediction = model.predict(data)
        # Return the prediction as a response
        return {"prediction": int(prediction[0])}
    except jwt.exceptions.DecodeError:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
if __name__ == "__main__":
    uvicorn.run(
        app, host="127.0.0.1", port=8000, ssl_keyfile="pem/key.pem", ssl_certfile="pem/cert.pem"
    )