from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from uuid import UUID
from datetime import datetime
from enum import Enum


# -----------------------------------------
# HTTP METHODS
# -----------------------------------------
class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


# -----------------------------------------
# AUTH TYPES
# -----------------------------------------
class AuthType(str, Enum):
    NONE = "NONE"
    BASIC = "BASIC"
    BEARER = "BEARER"
    API_KEY = "API_KEY"


class Authorization(BaseModel):
    type: AuthType = AuthType.NONE
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    api_key_name: Optional[str] = None
    api_key_value: Optional[str] = None


# -----------------------------------------
# COLLECTION SCHEMAS
# -----------------------------------------
class CreateCollection(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    parent_id: Optional[UUID] = Field(None, description="Parent collection ID for nested folders")


class UpdateCollection(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)


class CollectionResponse(BaseModel):
    id: UUID
    name: str
    parent_id: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime


# Recursive tree structure for nested collections (Frontend-friendly)
class CollectionTree(BaseModel):
    id: UUID
    name: str
    parent_id: Optional[UUID] = None
    collections: List["CollectionTree"] = Field(default_factory=list)
    requests: List["RequestResponse"] = Field(default_factory=list)

    class Config:
        from_attributes = True


# -----------------------------------------
# REQUEST SCHEMAS
# -----------------------------------------
class CreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    method: str = Field(..., description="HTTP Method or protocol action (GET, POST, PUBLISH, etc.)")
    url: str = Field(..., description="URL or connection string")
    
    headers: Dict[str, Any] = Field(default_factory=dict)
    body: Any = Field(default_factory=dict)  # Can be dict, string, or protocol-specific
    
    # Protocol-specific fields
    type: str = "HTTP"  # HTTP, GraphQL, MQTT, gRPC, etc.
    authorization: Authorization = Field(default_factory=Authorization)


class UpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    method: Optional[str] = None
    url: Optional[str] = None
    headers: Optional[Dict[str, Any]] = None
    body: Optional[Any] = None
    type: Optional[str] = None


class RequestResponse(BaseModel):
    id: UUID
    name: str
    method: str
    url: str
    type: str = "HTTP"
    headers: Dict[str, Any] = Field(default_factory=dict)
    body: Any = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Update forward reference for recursive model
CollectionTree.model_rebuild()

