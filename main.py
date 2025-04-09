from typing import Union

from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def welcome_message():
    return {"Hello": "Cloud Team"}