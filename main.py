from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from jose import jwt
import json
import os
import uuid
import base64

from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from database import Base, engine, get_db
import model

from pwdlib import PasswordHash


# =========================================================
# CONFIG
# =========================================================

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"


# =========================================================
# DATABASE
# =========================================================

Base.metadata.create_all(bind=engine)


# =========================================================
# FASTAPI
# =========================================================

app = FastAPI()


# Static files
app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)


# =========================================================
# IMAGE UPLOAD DIRECTORY
# =========================================================

UPLOAD_DIR = "static/uploads"

os.makedirs(
    UPLOAD_DIR,
    exist_ok=True
)


# =========================================================
# ACTIVE USERS
# username -> websocket
# =========================================================

active_users = {}


password_hash = PasswordHash.recommended()


# =========================================================
# AUTH MODEL
# =========================================================

class AuthRequest(BaseModel):
    username: str
    password: str


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():

    return RedirectResponse(
        url="/static/auth.html"
    )


# =========================================================
# SIGNUP
# =========================================================

@app.post("/signup")
def signup(
    data: AuthRequest,
    db: Session = Depends(get_db)
):

    user = db.query(model.Users).filter(
        model.Users.username == data.username
    ).first()

    if user:

        raise HTTPException(
            status_code=400,
            detail="User exists"
        )

    hashed_password = password_hash.hash(
        data.password
    )

    new_user = model.Users(
        username=data.username,
        password=hashed_password
    )

    db.add(new_user)

    db.commit()

    return {
        "message": "Signup success"
    }


# =========================================================
# LOGIN
# =========================================================

@app.post("/login")
def login(
    data: AuthRequest,
    db: Session = Depends(get_db)
):

    user = db.query(model.Users).filter(
        model.Users.username == data.username
    ).first()

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    if not password_hash.verify(
        data.password,
        user.password
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    token = jwt.encode(
        {
            "username": data.username
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return {
        "token": token,
        "username": data.username
    }


# =========================================================
# SAVE BASE64 IMAGE
# =========================================================

def save_base64_image(
    base64_data: str
):

    try:

        # Expected format:
        #
        # data:image/png;base64,AAAA....

        if "," not in base64_data:

            return None

        header, encoded = base64_data.split(
            ",",
            1
        )


        # =============================================
        # IMAGE EXTENSION
        # =============================================

        if "image/png" in header:

            extension = "png"

        elif "image/jpeg" in header:

            extension = "jpg"

        elif "image/jpg" in header:

            extension = "jpg"

        elif "image/webp" in header:

            extension = "webp"

        elif "image/gif" in header:

            extension = "gif"

        else:

            return None


        # =============================================
        # UNIQUE FILE NAME
        # =============================================

        filename = (
            f"{uuid.uuid4().hex}.{extension}"
        )


        filepath = os.path.join(
            UPLOAD_DIR,
            filename
        )


        # =============================================
        # DECODE IMAGE
        # =============================================

        image_bytes = base64.b64decode(
            encoded
        )


        # =============================================
        # SAVE IMAGE
        # =============================================

        with open(
            filepath,
            "wb"
        ) as file:

            file.write(
                image_bytes
            )


        # Browser URL
        return (
            f"/static/uploads/{filename}"
        )


    except Exception as e:

        print(
            "Image save error:",
            e
        )

        return None


# =========================================================
# PUBLIC / GROUP MESSAGE HISTORY
# =========================================================

@app.get("/messages")
def get_messages(
    db: Session = Depends(get_db)
):

    messages = db.query(
        model.Messages
    ).filter(

        # Group messages have no receiver
        model.Messages.receiver.is_(None),

        # Only public text/image
        model.Messages.message_type.in_(
            [
                "text",
                "image"
            ]
        )

    ).order_by(

        model.Messages.created_at.asc()

    ).all()

    return messages


# =========================================================
# PRIVATE MESSAGE HISTORY
# =========================================================

@app.get("/private-messages/{username}")
def get_private_messages(
    username: str,
    current_user: str,
    db: Session = Depends(get_db)
):

    """
    Return ONLY messages between:

        current_user <-> username

    Example:

        Himanshu -> Rahul
        Rahul -> Himanshu

    Will NOT return:

        Himanshu -> Amit
        Amit -> Himanshu
        Rahul -> Amit
        etc.
    """

    messages = db.query(
        model.Messages
    ).filter(

        # Private text + private image
        model.Messages.message_type.in_(
            [
                "private",
                "private_image"
            ]
        ),

        (
            (
                (model.Messages.sender == current_user)
                &
                (model.Messages.receiver == username)
            )
            |
            (
                (model.Messages.sender == username)
                &
                (model.Messages.receiver == current_user)
            )
        )

    ).order_by(

        model.Messages.created_at.asc()

    ).all()

    return messages


# =========================================================
# WEBSOCKET
# =========================================================

@app.websocket("/ws")
async def websocket_endpoint(
    ws: WebSocket,
    token: str,
    db: Session = Depends(get_db)
):

    await ws.accept()

    username = None


    try:

        # =================================================
        # VERIFY JWT
        # =================================================

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[
                ALGORITHM
            ]
        )

        username = payload["username"]


        # =================================================
        # USER ONLINE
        # =================================================

        active_users[username] = ws


        await broadcast_users()


        # =================================================
        # RECEIVE LOOP
        # =================================================

        while True:

            raw = await ws.receive_text()

            msg = json.loads(raw)

            message_type = msg.get(
                "type"
            )


            # =================================================
            # TYPING
            # =================================================

            if message_type == "typing":

                to = msg.get(
                    "to"
                )


                # -----------------------------------------
                # PRIVATE TYPING
                # -----------------------------------------

                if to:

                    await send_private_message(
                        to,
                        {
                            "type": "typing",
                            "user": username
                        }
                    )


                # -----------------------------------------
                # GROUP TYPING
                # -----------------------------------------

                else:

                    await broadcast_except(
                        username,
                        {
                            "type": "typing",
                            "user": username
                        }
                    )


            # =================================================
            # PUBLIC TEXT MESSAGE
            # =================================================

            elif message_type == "message":

                text = msg.get(
                    "data",
                    ""
                ).strip()


                if not text:

                    continue


                # -----------------------------------------
                # SAVE DATABASE
                # -----------------------------------------

                new_message = model.Messages(

                    sender=username,

                    receiver=None,

                    message=text,

                    message_type="text"

                )


                db.add(
                    new_message
                )

                db.commit()


                # -----------------------------------------
                # SEND TO EVERYONE
                # -----------------------------------------

                await broadcast(
                    {
                        "type": "message",

                        "user": username,

                        "text": text
                    }
                )


            # =================================================
            # PUBLIC IMAGE
            # =================================================

            elif message_type == "image":

                image_data = msg.get(
                    "data"
                )


                if not image_data:

                    continue


                # -----------------------------------------
                # SAVE IMAGE FILE
                # -----------------------------------------

                image_url = save_base64_image(
                    image_data
                )


                if not image_url:

                    continue


                # -----------------------------------------
                # SAVE DATABASE
                # -----------------------------------------

                new_message = model.Messages(

                    sender=username,

                    receiver=None,

                    message=image_url,

                    message_type="image"

                )


                db.add(
                    new_message
                )

                db.commit()


                # -----------------------------------------
                # BROADCAST IMAGE
                # -----------------------------------------

                await broadcast(
                    {
                        "type": "image",

                        "user": username,

                        "data": image_url
                    }
                )


            # =================================================
            # PRIVATE TEXT MESSAGE
            # =================================================

            elif message_type == "private":

                to = msg.get(
                    "to"
                )

                text = msg.get(
                    "data",
                    ""
                ).strip()


                # -----------------------------------------
                # VALIDATION
                # -----------------------------------------

                if not to:

                    continue

                if not text:

                    continue

                # Don't allow self chat
                if to == username:

                    continue


                # -----------------------------------------
                # SAVE PRIVATE MESSAGE
                # -----------------------------------------

                new_message = model.Messages(

                    sender=username,

                    receiver=to,

                    message=text,

                    message_type="private"

                )


                db.add(
                    new_message
                )

                db.commit()


                # -----------------------------------------
                # SEND ONLY TO RECEIVER
                # -----------------------------------------

                await send_private_message(

                    to,

                    {
                        "type": "private",

                        "from": username,

                        "to": to,

                        "text": text
                    }

                )


                # -----------------------------------------
                # SEND TO SENDER
                # -----------------------------------------

                await send_private_message(

                    username,

                    {
                        "type": "private",

                        "from": username,

                        "to": to,

                        "text": text,

                        "self": True
                    }

                )


            # =================================================
            # PRIVATE IMAGE
            # =================================================

            elif message_type == "private_image":

                to = msg.get(
                    "to"
                )

                image_data = msg.get(
                    "data"
                )


                # -----------------------------------------
                # VALIDATION
                # -----------------------------------------

                if not to:

                    continue

                if not image_data:

                    continue

                # Don't allow self chat
                if to == username:

                    continue


                # -----------------------------------------
                # SAVE IMAGE
                # -----------------------------------------

                image_url = save_base64_image(
                    image_data
                )


                if not image_url:

                    continue


                # -----------------------------------------
                # SAVE DATABASE
                # -----------------------------------------

                new_message = model.Messages(

                    sender=username,

                    receiver=to,

                    message=image_url,

                    message_type="private_image"

                )


                db.add(
                    new_message
                )

                db.commit()


                # -----------------------------------------
                # SEND ONLY TO RECEIVER
                # -----------------------------------------

                await send_private_message(

                    to,

                    {
                        "type": "private_image",

                        "from": username,

                        "to": to,

                        "data": image_url
                    }

                )


                # -----------------------------------------
                # SEND TO SENDER
                # -----------------------------------------

                await send_private_message(

                    username,

                    {
                        "type": "private_image",

                        "from": username,

                        "to": to,

                        "data": image_url,

                        "self": True
                    }

                )


    # =====================================================
    # DISCONNECT
    # =====================================================

    except WebSocketDisconnect:

        if username:

            active_users.pop(
                username,
                None
            )

            await broadcast_users()


    # =====================================================
    # ERROR
    # =====================================================

    except Exception as e:

        print(
            "WebSocket error:",
            e
        )

        if username:

            active_users.pop(
                username,
                None
            )

            await broadcast_users()


# =========================================================
# SEND PRIVATE MESSAGE
# =========================================================

async def send_private_message(
    to,
    message
):

    if to not in active_users:

        return


    try:

        await active_users[to].send_text(
            json.dumps(message)
        )


    except Exception:

        active_users.pop(
            to,
            None
        )


# =========================================================
# PUBLIC BROADCAST
# =========================================================

async def broadcast(
    message: dict
):

    disconnected_users = []


    for user, ws in list(
        active_users.items()
    ):

        try:

            await ws.send_text(
                json.dumps(message)
            )


        except Exception:

            disconnected_users.append(
                user
            )


    for user in disconnected_users:

        active_users.pop(
            user,
            None
        )


# =========================================================
# BROADCAST EXCEPT CURRENT USER
# =========================================================

async def broadcast_except(
    skip_user,
    message
):

    for user, ws in list(
        active_users.items()
    ):

        if user == skip_user:

            continue


        try:

            await ws.send_text(
                json.dumps(message)
            )


        except Exception:

            active_users.pop(
                user,
                None
            )


# =========================================================
# ONLINE USERS
# =========================================================

async def broadcast_users():

    await broadcast(
        {
            "type": "users",

            "users": list(
                active_users.keys()
            )
        }
    )