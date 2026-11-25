import hashlib
import os
import secrets
from contextlib import asynccontextmanager
from typing import Annotated
from uuid import UUID, uuid4

import psycopg
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

DATABASE_URL = os.environ["DATABASE_URL"]
ADMIN_TOKEN = os.environ["ADMIN_TOKEN"]

if len(ADMIN_TOKEN) < 32:
    raise RuntimeError("ADMIN_TOKEN debe tener al menos 32 caracteres.")

bearer = HTTPBearer()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    with psycopg.connect(DATABASE_URL) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS cuentas_saldo (
                id UUID PRIMARY KEY,
                token_hash BYTEA NOT NULL UNIQUE,
                saldo_centavos BIGINT NOT NULL DEFAULT 0
                    CHECK (saldo_centavos >= 0)
            )
        """)
    yield


app = FastAPI(lifespan=lifespan)
Credencial = Annotated[HTTPAuthorizationCredentials, Depends(bearer)]


def verificar_admin(credencial: Credencial):
    if not secrets.compare_digest(
        credencial.credentials.encode(), ADMIN_TOKEN.encode()
    ):
        raise HTTPException(403, "Acceso de administrador requerido.")


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


class AjusteSaldo(BaseModel):
    saldo_centavos: Annotated[int, Field(strict=True, ge=0, le=2_147_483_647)]


@app.post("/admin/cuentas", status_code=201, dependencies=[Depends(verificar_admin)])
def crear_cuenta():
    cuenta_id = uuid4()
    token = secrets.token_urlsafe(32)
    with psycopg.connect(DATABASE_URL) as db:
        db.execute(
            "INSERT INTO cuentas_saldo (id, token_hash) VALUES (%s, %s)",
            (cuenta_id, hash_token(token)),
        )
    return {"cuenta_id": cuenta_id, "token": token}


@app.put("/admin/cuentas/{cuenta_id}/saldo", dependencies=[Depends(verificar_admin)])
def fijar_saldo(cuenta_id: UUID, ajuste: AjusteSaldo):
    with psycopg.connect(DATABASE_URL) as db:
        fila = db.execute(
            """
            UPDATE cuentas_saldo SET saldo_centavos = %s
            WHERE id = %s RETURNING saldo_centavos
            """,
            (ajuste.saldo_centavos, cuenta_id),
        ).fetchone()

    if fila is None:
        raise HTTPException(404, "Cuenta no encontrada.")
    return {"saldo_centavos": fila[0], "moneda": "MXN"}


@app.get("/saldo")
def consultar_saldo(credencial: Credencial):
    with psycopg.connect(DATABASE_URL) as db:
        fila = db.execute(
            "SELECT saldo_centavos FROM cuentas_saldo WHERE token_hash = %s",
            (hash_token(credencial.credentials),),
        ).fetchone()

    if fila is None:
        raise HTTPException(401, "Token de cuenta inválido.")
    return {"saldo_centavos": fila[0], "moneda": "MXN"}
