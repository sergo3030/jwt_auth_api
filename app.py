from datetime import datetime
from typing import Annotated

import uvicorn
from fastapi import FastAPI, Security, Response

import utils as utils
from config import config
from routers import auth_token
from routers.auth_token import retrieve_access_token_data
from schemas import AccessTokenData

server_conf = config["server"]

app = FastAPI()
app.include_router(auth_token.router)

logger = utils.initiate_logger(__name__)


@app.get("/")
async def get_ok():
    return "ok"


@app.get("/api/ok")
async def health_check(access_token_data: Annotated[AccessTokenData, Security(retrieve_access_token_data,
                                                                              scopes=["view", "edit", "admin"])]):
    return {"response": "ok",
            "message": f"{access_token_data.username} requested health check",
            "timestamp": f"{datetime.now()}"}


@app.post("/logout")
async def logout(response: Response,
                 user_data: Annotated[AccessTokenData, Security(retrieve_access_token_data,
                                                                scopes=["view", "edit", "admin"])]):
    logger.info(msg=f"User {user_data.username} performs logout")
    response.delete_cookie("access_token")
    response.delete_cookie("csrf_token")
    response.set_cookie(key="refresh_token", value="", httponly=True, secure=False, path="/token/refresh")
    return {"username": f"{user_data.username}",
            "message": f"Successful logout",
            "timestamp": f"{datetime.now()}"}


if __name__ == "__main__":
    uvicorn.run("app:app",
                host=server_conf["host"],
                port=server_conf["port"],
                log_level=server_conf["log_level"])
