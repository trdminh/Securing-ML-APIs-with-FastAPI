'''
Use api key
'''

import joblib
from fastapi import FastAPI, HTTPException, Header,Depends
from pydantic import BaseModel
import secrets
model = joblib.load("model.pkl")

app = FastAPI()


class PredictionRequest(BaseModel):
    sepal_length: float
    sepal_width: float
    petal_length: float
    petal_width: float
    

API_Key = "123456"
def get_api_key(api_key: str = Header(None)):
    if api_key is None or api_key != API_Key:
        raise HTTPException(status_code=403, detail="Invalid API Key")

@app.post('/predict')
def predict(request: PredictionRequest, 
                        #added argument to get API key from user
            api_key: str = Depends(get_api_key)):
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

# API_Key = secrets.token_hex(16)
# print(f"API Key: {API_Key}")


