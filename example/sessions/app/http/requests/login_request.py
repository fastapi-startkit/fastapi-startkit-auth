"""Login request schema.

A plain Pydantic `BaseModel` (not the framework's form-encoded `RequestModel`)
so `POST /login` keeps parsing a JSON body — the wire format Inertia/axios
sends.
"""
from pydantic import BaseModel


class LoginRequest(BaseModel):
    email: str
    password: str
