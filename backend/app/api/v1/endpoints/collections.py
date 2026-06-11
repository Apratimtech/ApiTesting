from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.orm import Session, selectinload
from uuid import UUID
from datetime import datetime
from app.db.postgres import get_db
from app.models.sidebar import Collection, SavedRequest
from app.schemas.collection import (
    CreateCollection,
    UpdateCollection,
    CreateRequest,
    UpdateRequest,
    CollectionTree,
    RequestResponse
)

router = APIRouter(tags=["Collections"])


# =========================================================
# HELPER: Build Recursive Tree
# =========================================================
def build_tree(collection: Collection) -> dict:
    requests = []
    for req in collection.requests:
        requests.append({
            "id": str(req.id),
            "name": req.name,
            "method": req.method,
            "url": req.url,
            "headers": req.headers or {},
            "body": req.body,
            "type": getattr(req, "type", "HTTP"),
            "created_at": req.created_at,
            "updated_at": req.updated_at,
        })

    children = [build_tree(child) for child in collection.children]

    return {
        "id": str(collection.id),
        "name": collection.name,
        "parent_id": str(collection.parent_id) if collection.parent_id else None,
        "requests": requests,
        "collections": children,
        "created_at": collection.created_at,
        "updated_at": collection.updated_at,
    }


# =========================================================
# GET ALL COLLECTIONS (Recursive Tree)
# =========================================================
@router.get("/", status_code=status.HTTP_200_OK)
def get_all_collections(db: Session = Depends(get_db)):
    # Load root collections with eager loading
    root_collections = (
        db.query(Collection)
        .options(
            selectinload(Collection.children),
            selectinload(Collection.requests)
        )
        .filter(Collection.parent_id == None)
        .all()
    )

    data = [build_tree(col) for col in root_collections]

    return {
        "success": True,
        "count": len(data),
        "data": data,
    }


# =========================================================
# GET SINGLE COLLECTION
# =========================================================
@router.get("/{collection_id}", status_code=status.HTTP_200_OK)
def get_collection(collection_id: UUID, db: Session = Depends(get_db)):
    collection = (
        db.query(Collection)
        .options(selectinload(Collection.requests), selectinload(Collection.children))
        .filter(Collection.id == collection_id)
        .first()
    )

    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")

    return {
        "success": True,
        "data": build_tree(collection),
    }


# =========================================================
# CREATE COLLECTION (Supports Nested)
# =========================================================
@router.post("/", status_code=status.HTTP_201_CREATED)
def create_collection(
    data: CreateCollection,
    db: Session = Depends(get_db),
):
    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Collection name cannot be empty")

    # Check for duplicate at same level
    existing = (
        db.query(Collection)
        .filter(
            Collection.name == name,
            Collection.parent_id == data.parent_id
        )
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="A collection with this name already exists at this level"
        )

    collection = Collection(
        name=name,
        parent_id=data.parent_id
    )

    db.add(collection)
    db.commit()
    db.refresh(collection)

    return {
        "success": True,
        "message": "Collection created successfully",
        "data": {
            "id": str(collection.id),
            "name": collection.name,
            "parent_id": str(collection.parent_id) if collection.parent_id else None,
            "created_at": collection.created_at,
            "updated_at": collection.updated_at,
        },
    }


# =========================================================
# UPDATE COLLECTION (Rename)
# =========================================================
@router.put("/{collection_id}", status_code=status.HTTP_200_OK)
def update_collection(
    collection_id: UUID,
    data: UpdateCollection,
    db: Session = Depends(get_db),
):
    collection = db.get(Collection, collection_id)
    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")

    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Collection name cannot be empty")

    # Check duplicate at same parent level
    existing = (
        db.query(Collection)
        .filter(
            Collection.name == name,
            Collection.parent_id == collection.parent_id,
            Collection.id != collection_id
        )
        .first()
    )

    if existing:
        raise HTTPException(status_code=409, detail="Name already exists at this level")

    collection.name = name
    collection.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(collection)

    return {
        "success": True,
        "message": "Collection updated successfully",
        "data": {
            "id": str(collection.id),
            "name": collection.name,
            "parent_id": str(collection.parent_id) if collection.parent_id else None,
        },
    }


# =========================================================
# DELETE COLLECTION (Cascade handled by model)
# =========================================================
@router.delete("/{collection_id}", status_code=status.HTTP_200_OK)
def delete_collection(
    collection_id: UUID,
    db: Session = Depends(get_db),
):
    collection = db.get(Collection, collection_id)
    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")

    db.delete(collection)
    db.commit()

    return {
        "success": True,
        "message": "Collection and all nested content deleted successfully",
    }


# =========================================================
# ADD REQUEST TO COLLECTION
# =========================================================
@router.post("/{collection_id}/request", status_code=status.HTTP_201_CREATED)
def add_request_to_collection(
    collection_id: UUID,
    data: CreateRequest,
    db: Session = Depends(get_db),
):
    collection = db.get(Collection, collection_id)
    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")

    request_obj = SavedRequest(
        collection_id=collection_id,
        name=data.name.strip(),
        method=data.method,
        url=data.url,
        headers=data.headers,
        body=data.body,
        type=data.type,  # Uncomment when SavedRequest model supports 'type' column
    )

    db.add(request_obj)
    db.commit()
    db.refresh(request_obj)

    return {
        "success": True,
        "message": "Request added successfully",
        "data": RequestResponse.model_validate(request_obj).model_dump(),
    }


# =========================================================
# UPDATE REQUEST
# =========================================================
@router.put("/request/{request_id}")
def update_request(
    request_id: UUID,
    data: UpdateRequest,
    db: Session = Depends(get_db),
):
    request_obj = db.get(SavedRequest, request_id)
    if not request_obj:
        raise HTTPException(status_code=404, detail="Request not found")

    if data.name is not None:
        request_obj.name = data.name.strip()
    if data.method is not None:
        request_obj.method = data.method
    if data.url is not None:
        request_obj.url = data.url
    if data.headers is not None:
        request_obj.headers = data.headers
    if data.body is not None:
        request_obj.body = data.body

    request_obj.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(request_obj)

    return {
        "success": True,
        "message": "Request updated successfully",
        "data": RequestResponse.model_validate(request_obj).model_dump(),
    }


# =========================================================
# DELETE REQUEST
# =========================================================
@router.delete("/request/{request_id}")
def delete_request(
    request_id: UUID,
    db: Session = Depends(get_db),
):
    request_obj = db.get(SavedRequest, request_id)
    if not request_obj:
        raise HTTPException(status_code=404, detail="Request not found")

    db.delete(request_obj)
    db.commit()

    return {
        "success": True,
        "message": "Request deleted successfully",
    }
