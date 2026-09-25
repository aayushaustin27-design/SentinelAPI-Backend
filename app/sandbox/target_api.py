from fastapi import FastAPI, Depends, HTTPException, status, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any

sandbox_app = FastAPI(
    title="SentinelAPI Vulnerable Sandbox Test Target",
    description="Intentionally vulnerable sandbox API for local security auditing (BOLA, Excessive Data Exposure, Auth Misconfig, Rate Limiting).",
    version="1.0.0",
    docs_url="/docs",
    openapi_url="/openapi.json"
)

# -----------------------------------------------------------------------------
# In-Memory Mock Database
# -----------------------------------------------------------------------------
USERS_DB = {
    "user_a": {
        "id": "usr_101",
        "username": "user_a",
        "password": "password_a",
        "token": "token_user_a",
        "profile": {
            "id": "usr_101",
            "username": "user_a",
            "email": "user_a@example.com",
            "full_name": "Alice Johnson",
            "role": "standard_user",
            "phone": "+1-555-0101",
            "ssn_last_four": "9876",
            "address": "123 Maple St, Springfield"
        }
    },
    "user_b": {
        "id": "usr_102",
        "username": "user_b",
        "password": "password_b",
        "token": "token_user_b",
        "profile": {
            "id": "usr_102",
            "username": "user_b",
            "email": "user_b@example.com",
            "full_name": "Bob Smith",
            "role": "standard_user",
            "phone": "+1-555-0102",
            "ssn_last_four": "5432",
            "address": "456 Oak Ave, Metropolis"
        }
    }
}

TOKEN_TO_USER = {
    "token_user_a": USERS_DB["user_a"],
    "token_user_b": USERS_DB["user_b"],
}

USER_ID_TO_PROFILE = {
    "usr_101": USERS_DB["user_a"]["profile"],
    "usr_102": USERS_DB["user_b"]["profile"],
}

ORDERS_DB = {
    "ord_9001": {
        "order_id": "ord_9001",
        "user_id": "usr_101",
        "item": "Premium Security Course",
        "amount": 299.99,
        "status": "completed",
        # Excessive data exposure fields:
        "password_hash": "$2b$12$e8Yx9p.L2v1Hk7VjL6ZkQOQnZ1xK8JbO4f3M2vX6mP.QwErTyUiOp",
        "internal_routing_key": "kafka-cluster-prod-east.internal.order-events.key-88912",
        "stripe_customer_id": "cus_N9Xm8Qw92KpL"
    },
    "ord_9002": {
        "order_id": "ord_9002",
        "user_id": "usr_102",
        "item": "Cloud Security Architecture Toolkit",
        "amount": 499.00,
        "status": "processing",
        # Excessive data exposure fields:
        "password_hash": "$2b$12$j4V9kX.M3w2Il8WkM7AlRPPnZ2yL9KcQ5g4N3wY7nP.RxFsUzVjPq",
        "internal_routing_key": "kafka-cluster-prod-east.internal.order-events.key-88913",
        "stripe_customer_id": "cus_M3Lk8Pn73TqV"
    }
}

# -----------------------------------------------------------------------------
# Schemas & Auth Dependency
# -----------------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str

class TransferRequest(BaseModel):
    amount: float
    recipient: str

def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"}
        )
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization scheme. Expected 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"}
        )
    token = parts[1]
    user = TOKEN_TO_USER.get(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Bearer token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user

# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------
@sandbox_app.get("/api/v1/health", tags=["System"])
def health_check():
    """Healthcheck endpoint for scanner liveness probe."""
    return {"status": "ok", "service": "sentinel-vulnerable-sandbox", "version": "1.0.0"}

@sandbox_app.get("/api/v1/public/debug", tags=["Diagnostics"])
def public_debug_info():
    """Vulnerability: Unauthenticated diagnostic exposure."""
    return {
        "debug_mode": True,
        "environment": "sandbox-staging",
        "service_cluster": "cluster-us-east-1.internal",
        "active_threads": 4,
        "runtime": "python-3.11-fastapi"
    }

@sandbox_app.post("/auth/login", response_model=LoginResponse, tags=["Authentication"])
def login(creds: LoginRequest):
    """
    Issues mock Bearer tokens:
    - User A: username="user_a", password="password_a"
    - User B: username="user_b", password="password_b"
    """
    user = USERS_DB.get(creds.username)
    if not user or user["password"] != creds.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    return LoginResponse(
        access_token=user["token"],
        token_type="bearer",
        user_id=user["id"]
    )

@sandbox_app.get("/api/v1/users/{user_id}/profile", tags=["Users"])
def get_user_profile(user_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    BOLA / IDOR Vulnerability:
    Accepts any authenticated user's token, but DOES NOT verify that current_user['id'] == user_id.
    """
    profile = USER_ID_TO_PROFILE.get(user_id)
    if not profile:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return profile

@sandbox_app.get("/api/v1/orders/{order_id}", tags=["Orders"])
def get_order(order_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Excessive Data Exposure Vulnerability:
    Leaking internal system properties (password_hash, internal_routing_key, stripe_customer_id).
    """
    order = ORDERS_DB.get(order_id)
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")
    return order

@sandbox_app.post("/api/v1/transfers/quick", tags=["Transfers"])
def quick_transfer(transfer: TransferRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Missing Rate Limiting Vulnerability:
    Processes rapid concurrent burst transfers without throttling.
    """
    return {
        "status": "success",
        "sender": current_user["username"],
        "recipient": transfer.recipient,
        "amount": transfer.amount,
        "transaction_id": f"tx_{int(transfer.amount * 1000)}"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("target_api:sandbox_app", host="127.0.0.1", port=8001, reload=True)
