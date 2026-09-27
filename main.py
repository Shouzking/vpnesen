import json
import os
import subprocess
import uuid
from itertools import count
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="WireGuard API",
    description="API для управления WireGuard-клиентами",
    version="1.1.0",
)

# ---------------------------------------------------------------------------
# Хранилище: JSON-файл, чтобы клиенты не терялись при перезапуске
# ---------------------------------------------------------------------------

DB_PATH = os.getenv("WG_DB_PATH", "clients.json")


def _load_db() -> dict:
    if not os.path.exists(DB_PATH):
        return {"clients": {}, "next_id": 1}
    with open(DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_db(db: dict) -> None:
    tmp = DB_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    os.replace(tmp, DB_PATH)  # атомарная запись — не останемся с битым файлом


db = _load_db()
clients: dict[int, dict] = {int(k): v for k, v in db["clients"].items()}
_id_counter = count(db.get("next_id", 1))


# ---------------------------------------------------------------------------
# Pydantic-модели
# ---------------------------------------------------------------------------

class ClientCreate(BaseModel):
    name: str
    description: Optional[str] = None


class Client(BaseModel):
    id: int
    name: str
    description: Optional[str] = None


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

def _generate_keypair() -> tuple[str, str]:
    """Генерация приватного/публичного ключей WireGuard через wg genkey."""
    try:
        priv = subprocess.run(
            ["wg", "genkey"], capture_output=True, text=True, check=True
        ).stdout.strip()
        pub = subprocess.run(
            ["wg", "pubkey"], input=priv, capture_output=True, text=True, check=True
        ).stdout.strip()
        return priv, pub
    except (FileNotFoundError, subprocess.CalledProcessError):
        raise HTTPException(
            status_code=500,
            detail="wireguard-tools (wg) не установлен или недоступен",
        )


def _next_id() -> int:
    """Монотонный id: не пересекается после удаления клиентов."""
    cid = next(_id_counter)
    db["next_id"] = cid + 1
    return cid


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "clients": len(clients)}


@app.get("/panel")
def panel():
    return {
        "message": "WireGuard panel",
        "status": "ok",
        "clients_total": len(clients),
    }


@app.get("/api/routes")
def routes():
    """Список маршрутов генерируется автоматически — не нужно править вручную."""
    result = []
    for route in app.routes:
        methods = getattr(route, "methods", None)
        if methods:
            for method in sorted(methods):
                if method != "HEAD":
                    result.append(f"{method} {route.path}")
    return {"routes": sorted(result)}


@app.post("/api/wg/clients", status_code=201, response_model=Client)
def create_client(client: ClientCreate):
    client_id = _next_id()
    priv, pub = _generate_keypair()

    clients[client_id] = {
        "id": client_id,
        "name": client.name,
        "description": client.description,
        "public_key": pub,
        "_private_key": priv,  # храним для выдачи конфига
    }
    db["clients"] = {str(k): v for k, v in clients.items()}
    _save_db(db)
    return clients[client_id]


@app.get("/api/wg/clients")
def get_clients():
    return {
        "clients": [
            {k: v for k, v in c.items() if not k.startswith("_")}
            for c in clients.values()
        ]
    }


@app.get("/api/wg/clients/{client_id}/config")
def get_client_config(client_id: int):
    client = clients.get(client_id)
    if client is None:
        raise HTTPException(status_code=404, detail="Client not found")

    server_endpoint = os.getenv("WG_SERVER_ENDPOINT", "vpn.example.com:51820")
    server_public_key = os.getenv("WG_SERVER_PUBLIC_KEY", "SERVER_PUBLIC_KEY_HERE")
    client_ip = os.getenv("WG_CLIENT_IP", "10.0.0.2/32")

    config = f"""[Interface]
PrivateKey = {client['_private_key']}
Address = {client_ip}
DNS = 1.1.1.1

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_endpoint}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    return {"client_id": client_id, "config": config}


@app.delete("/api/wg/clients/{client_id}")
def delete_client(client_id: int):
    client = clients.pop(client_id, None)
    if client is None:
        raise HTTPException(status_code=404, detail="Client not found")

    db["clients"] = {str(k): v for k, v in clients.items()}
    _save_db(db)
    return {"message": "Client deleted", "client": client}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
