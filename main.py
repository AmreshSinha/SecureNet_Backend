from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from typing import List
import models
from database import engine, SessionLocal
from sqlalchemy.orm import Session

app = FastAPI()
models.Base.metadata.create_all(bind=engine)

class AppCreate(BaseModel):
    package_name: str
    app_name: str
    version_code: int
    version_name: str
    file_size: int
    permissions: List[str]
    is_system_app: bool
    is_malicious: bool
    threat_category: str = None
    static_analysis_results: str = None
    dynamic_analysis_results: str = None

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close() 

db_dependency = Depends(get_db)

class AppResponse(BaseModel):
    message: str
    app_id: int

# Endpoint to create a new app entry
@app.post("/apps/", response_model=AppResponse)
async def create_app(app_data: AppCreate, db: Session = db_dependency):
    try:
        # Convert Pydantic model to SQLAlchemy model
        db_app = models.AppDBModel(**app_data.dict())

        # Store the data in the database
        db.add(db_app)
        db.commit()
        db.refresh(db_app)

        return {"message": "App created successfully", "app_id": db_app.id}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/apps/", response_model=List[AppResponse])
async def list_apps(db: Session = db_dependency):
    apps = db.query(models.AppDBModel).all()
    
    return [
        AppResponse(
            app_id=app.id,
            package_name=app.package_name,
            app_name=app.app_name,
            version_code=app.version_code,
            version_name=app.version_name,
            file_size=app.file_size,
            permissions=app.permissions,
            is_system_app=app.is_system_app,
            is_malicious=app.is_malicious,
            threat_category=app.threat_category,
            static_analysis_results=app.static_analysis_results,
            dynamic_analysis_results=app.dynamic_analysis_results
        )
        for app in apps
    ]