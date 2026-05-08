from fastapi import APIRouter, HTTPException, status
from uuid import uuid4
from datetime import datetime

from app.services.storage import storage
from app.schemas.collection import (
    CreateCollection,
    CreateRequest
)

router = APIRouter(
    prefix="/collections",
    tags=["Collections"]
)


# =========================================================
# 🔹 GET ALL COLLECTIONS
# =========================================================
@router.get("/", status_code=status.HTTP_200_OK)
async def get_all_collections():

    collections = storage.all_collections()

    return {
        "success": True,
        "count": len(collections),
        "data": collections
    }


# =========================================================
# 🔹 CREATE COLLECTION
# =========================================================
@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_collection(data: CreateCollection):

    collection = {
        "id": str(uuid4()),
        "name": data.name.strip(),
        "requests": [],
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }

    storage.add_collection(collection["id"], collection)

    return {
        "success": True,
        "message": "Collection created successfully",
        "data": collection
    }


# =========================================================
# 🔹 ADD REQUEST TO COLLECTION
# =========================================================
@router.post("/{collection_id}/request")
async def add_request_to_collection(
    collection_id: str,
    data: CreateRequest
):

    collection = storage.get_collection(collection_id)

    if not collection:
        raise HTTPException(
            status_code=404,
            detail="Collection not found"
        )

    request_data = {
        "id": str(uuid4()),
        "name": data.name.strip(),
        "method": data.method.value,
        "url": str(data.url),
        "headers": data.headers,
        "body": data.body,
        "collection_id": collection_id,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }

    collection["requests"].append(request_data)

    return {
        "success": True,
        "message": "Request added successfully",
        "data": request_data
    }


# =========================================================
# 🔹 DELETE REQUEST
# =========================================================
@router.delete("/request/{request_id}")
async def delete_request(request_id: str):

    collections = storage.all_collections()

    for collection in collections:

        original_count = len(collection["requests"])

        collection["requests"] = [
            req for req in collection["requests"]
            if req["id"] != request_id
        ]

        if len(collection["requests"]) < original_count:

            return {
                "success": True,
                "message": "Request deleted successfully"
            }

    raise HTTPException(
        status_code=404,
        detail="Request not found"
    )


# =========================================================
# 🔹 UPDATE REQUEST
# =========================================================
@router.put("/request/{request_id}")
async def update_request(
    request_id: str,
    data: CreateRequest
):

    collections = storage.all_collections()

    for collection in collections:

        for request_item in collection["requests"]:

            if request_item["id"] == request_id:

                request_item.update({
                    "name": data.name.strip(),
                    "method": data.method.value,
                    "url": str(data.url),
                    "headers": data.headers,
                    "body": data.body,
                    "updated_at": datetime.utcnow().isoformat()
                })

                return {
                    "success": True,
                    "message": "Request updated successfully",
                    "data": request_item
                }

    raise HTTPException(
        status_code=404,
        detail="Request not found"
    )
