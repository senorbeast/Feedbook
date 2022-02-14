import jwt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.hash import bcrypt
from tortoise import fields
from tortoise.contrib.fastapi import register_tortoise
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.models import Model

# Server side
# Create User DB with ORM
# Create user, store hashed password in db
# Auth func, verify_password
# Generate (JWT) token for authed user, payload encoded with JWTsecret
# Generate payload by decoding JWT

# JWT : Crypted payload (username mostly)

JWT_SECRET = "jwt_secret"
app = FastAPI()

# Our User Table
class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique=True)
    password_hash = fields.CharField(128)

    @classmethod
    async def get_user(cls, username):
        return cls.get(username=username)

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)


register_tortoise(
    app,
    db_url="sqlite://db.sqlite3",
    modules={"models": ["main"]},
    generate_schemas=True,
    add_exception_handlers=True,
)

# Type defn for User and UserIn
User_Pydantic = pydantic_model_creator(User, name="User")
UserIn_Pydantic = pydantic_model_creator(User, name="UserIn", exclude_readonly=True)


# Create User (Taking in data in User type, response of also of User Type)
@app.post("/users", response_model=User_Pydantic)
async def create_user(user: UserIn_Pydantic):
    user_obj = User(
        username=user.username, password_hash=bcrypt.hash(user.password_hash)
    )
    await user_obj.save()  # Saving user to db
    return await User_Pydantic.from_tortoise_orm(user_obj)  # response


async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False
    if not user.verify_password(password):
        return False
    # if  both user, password pass
    return user


# Generating JWT for user
@app.post("/token")
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    # if user is auth
    user_obj = await User_Pydantic.from_tortoise_orm(user)
    user_obj = user_obj.dict()
    # Encoding token with JWT secret
    user_id_n = dict((k, user_obj[k]) for k in ["id", "username"] if k in user_obj)
    token = jwt.encode(user_id_n, JWT_SECRET)
    return {"access_token": token, "token_type": "bearer"}


# Add this in Depends or any of the Depends parent to req the endpoint to get auth
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        # print(payload)
        user = await User.get(id=payload.get("id"))
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    return await User_Pydantic.from_tortoise_orm(user)


# To get user payload (decoded JWT)
@app.get("/users/me", response_model=User_Pydantic)
async def get_user(user: User_Pydantic = Depends(get_current_user)):
    return user
