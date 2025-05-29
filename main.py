#!/usr/bin/env python3

import os
import logging

from typing import Annotated
from fastapi import FastAPI, HTTPException, Depends, Security, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, APIKeyHeader
from pydantic import BaseModel
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.config import Config
from typing import List, Optional
from dotenv import load_dotenv
from jose import JWTError, jwt
from datetime import datetime, timedelta

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Setup DynamoDB connection
aws_region = os.getenv('AWS_REGION')
table_name = os.getenv('DYNAMODB_TABLE_NAME')
user_id = os.getenv('USER_ID', 'admin')
password = os.getenv('PASSWORD', 'Admin1234')
master_api_key = os.getenv('API_KEY')

endpoint_url = os.getenv('AWS_ENDPOINT_URL', None)
logger.info(f"aws_region: {aws_region}, table_name: {table_name}")
logger.info(f"endpoint_url: {endpoint_url}")

config = Config(
    region_name=aws_region,
    endpoint_discovery_enabled=False
)
    # config=config,
    # endpoint_url=endpoint_url,

dynamodb = boto3.resource(
    'dynamodb',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID', ''),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY', '')
)

table = dynamodb.Table(table_name)

# Token-based authentication setup
SECRET_KEY = os.getenv('SECRET_KEY', '')
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
api_key_header = APIKeyHeader(name="X-API-Key")

class Item(BaseModel):
    id: str
    data: dict

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

def fake_hash_password(password: str):
    return "fakehashed" + password

fake_users_db = {
    user_id: {
        "username": user_id,
        "full_name": "",
        "email": "",
        "hashed_password": fake_hash_password(password),
        "disabled": False,
    }
}

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not user.hashed_password == fake_hash_password(password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def get_api_key(api_key: str = Security(api_key_header)):
    if api_key != master_api_key:
        raise HTTPException(status_code=403, detail="Could not validate API key")
    return api_key

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/items/")
#async def get_items(key: str, value: str, current_user: User = Depends(get_current_active_user), api_key: str = Depends(get_api_key)):
async def get_items(key: Annotated[str | None, Header()], value: Annotated[str | None, Header()], api_key: str = Depends(get_api_key)):
    logger.info(f"Fetching items with {key} = {value}")
    try:
        response = table.scan(
            FilterExpression=Attr(key).eq(value)
        )
        items = response.get('Items', [])
        logger.info(f"Found {len(items)} items")
        logger.info(items)
        return items
    except Exception as e:
        logger.error(f"Error fetching items: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/items/{item_id}")
#async def get_item(item_id: str, current_user: User = Depends(get_current_active_user), api_key: str = Depends(get_api_key)):
async def get_item(item_id: str, key: Annotated[str | None, Header()], value: Annotated[str | None, Header()], api_key: str = Depends(get_api_key)):
    logger.info(f"Fetching items with partition_key {key} = {value} and sort_key = {item_id}")
    try:
        key = { 'tenant_id': value, 
                'medical_record_number': item_id
            }
        print(key)
        response = table.get_item(Key=key)
        item = response.get('Item')
        logger.info(item)
        if not item:
            logger.warning(f"Item with id {item_id} not found")
            raise HTTPException(status_code=404, detail="Item not found")
        return [item]
    except Exception as e:
        logger.error(f"Error fetching item: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/items/")
#async def create_item(item: Item, current_user: User = Depends(get_current_active_user), api_key: str = Depends(get_api_key)):
async def create_item(item: Item, api_key: str = Depends(get_api_key)):
    logger.info(f"Creating item with id = {item.id}")
    try:
        table.put_item(Item=item.dict())
        logger.info(f"Item with id {item.id} created successfully")
        return {"message": "Item created successfully"}
    except Exception as e:
        logger.error(f"Error creating item: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/items/{item_id}")
#async def update_item(item_id: str, item: Item, current_user: User = Depends(get_current_active_user), api_key: str = Depends(get_api_key)):
async def update_item(item_id: str, item: Item,  api_key: str = Depends(get_api_key)):
    logger.info(f"Updating item with id = {item_id}")
    try:
        table.update_item(
            Key={'id': item_id},
            UpdateExpression="set data=:d",
            ExpressionAttributeValues={':d': item.data},
            ReturnValues="UPDATED_NEW"
        )
        logger.info(f"Item with id {item_id} updated successfully")
        return {"message": "Item updated successfully"}
    except Exception as e:
        logger.error(f"Error updating item: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/items/{item_id}")
#async def delete_item(item_id: str, current_user: User = Depends(get_current_active_user), api_key: str = Depends(get_api_key)):
async def delete_item(item_id: str, api_key: str = Depends(get_api_key)):
    logger.info(f"Deleting item with id = {item_id}")
    try:
        table.delete_item(Key={'id': item_id})
        logger.info(f"Item with id {item_id} deleted successfully")
        return {"message": "Item deleted successfully"}
    except Exception as e:
        logger.error(f"Error deleting item: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/healthcheck/")
async def healthcheck():
    logger.info("Healthcheck endpoint called")
    return [{"status": "ok"}]
