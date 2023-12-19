from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Response, Request
from pydantic import BaseModel
from typing import List
import models
from database import engine, SessionLocal
from sqlalchemy.orm import Session
import shutil
from dotenv import load_dotenv
import os
import requests
import hashlib
import time
from requests_toolbelt.multipart.encoder import MultipartEncoder
from ipdata_utils import ip_report
import json
from redis_utils import check_ip_report, add_ip_report, check_domain_report, add_domain_report
from spamhaus_utils import domain_report
import urllib.parse

load_dotenv()

app = FastAPI()

fcmToken = ""

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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


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


@app.post("/static/upload")
async def upload_apk(file: UploadFile = File(...)):
    """Upload route (POST) for the APK file

    Args:
        file (UploadFile, optional): _description_. Defaults to File(...).

    Raises:
        HTTPException: _description_

    Returns:
        _type_: _description_

    Example:
        Command: `curl -F 'file=@./example.apk' http://<api-server-endpoint>/static/upload`

        Response: 
        ```json
        {
            "mobsf_static": {
                "analyzer":"static_analyzer",
                "status":"success",
                "hash":"5f06b231c5e9b1703b088ad87050c89f",
                "scan_type":"apk",
                "file_name":"temp_example.apk"
            },
            "file_md5":"d25ebd002f0cce403f023c0840b2096d2ea34ddc"
        }
        ```
    """
    try:
        mobsf_api_url = f"{os.environ['MOBSF_ENDPOINT']}/api/v1/upload"
        temp_file_path = f"temp_{file.filename}"

        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Calculate the SHA hash of the file
        sha_hash = hashlib.md5()
        with open(temp_file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha_hash.update(chunk)

        file_hash = sha_hash.hexdigest()
        print(
            f"SHA256 Hash of the file {file.filename}: {file_hash}")

        time.sleep(1)  # !TEST

        with open(temp_file_path, "rb") as f:
            multipart_data = MultipartEncoder(
                fields={'file': (temp_file_path, f, 'application/octet-stream')})
            response = requests.post(
                mobsf_api_url,
                data=multipart_data,
                headers={'Content-Type': multipart_data.content_type,
                         "Authorization": os.environ['MOBSF_API_KEY']}
            )

        os.remove(temp_file_path)

        # Scan
        response = requests.post(f"{os.environ['MOBSF_ENDPOINT']}/api/v1/scan",
                                 data={
                                     "hash": file_hash
                                 },
                                 headers={
                                     "Authorization": os.environ['MOBSF_API_KEY']}
                                 )

        return {"static": response.json(), "file_md5": file_hash}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/static/scorecard")
async def scorecard(hash: str):
    """Scorecard route (GET) for the APK file

    Args:
        hash (str): MD5 hash of the APK file

    Raises:
        HTTPException: _description_

    Returns:
        _type_: _description_

    Example:
        Command: `curl http://<api-server-endpoint>/static/scorecard?hash=5f06b231c5e9b1703b088ad87050c89f`

        Response: JSON object
    """
    try:
        mobsf_api_url = f"{os.environ['MOBSF_ENDPOINT']}/api/v1/scorecard"
        response = requests.post(
            mobsf_api_url,
            data={'hash': hash},
            headers={"Authorization": os.environ['MOBSF_API_KEY']}
        )
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/static/report_json")
async def report_json(hash: str):
    """Report JSON route (GET) for the APK file

    Args:
        hash (str): MD5 hash of the APK file

    Raises:
        HTTPException: _description_

    Returns:
        _type_: _description_

    Example:
        Command: `curl http://<api-server-endpoint>/static/report_json?hash=5f06b231c5e9b1703b088ad87050c89f`

        Response: JSON object
    """
    try:
        mobsf_api_url = f"{os.environ['MOBSF_ENDPOINT']}/api/v1/report_json"
        response = requests.post(
            mobsf_api_url,
            data={'hash': hash},
            headers={"Authorization": os.environ['MOBSF_API_KEY']}
        )
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/static/report_pdf")
async def report_pdf(hash: str):
    """Report PDF route (GET) for the APK file

    Args:
        hash (str): MD5 hash of the APK file

    Raises:
        HTTPException: _description_

    Returns:
        _type_: _description_

    Example:
        Command: `curl http://<api-server-endpoint>/pdf?hash=5f06b231c5e9b1703b088ad87050c89f`

        Response: PDF file
    """
    try:
        query = f"{os.environ['MOBSF_ENDPOINT']}/pdf/{hash}/"
        print(query)
        response = requests.get(query)
        return Response(content=response.content, media_type="application/pdf")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/fcm")
async def report_pdf(request: Request):
    data = await request.json()
    token = data.get("token")
    global fcmToken
    fcmToken = token
    return {"success": True}


async def send_notif(title: str, body: str):
    global fcmToken
    if fcmToken == "":
        return {"message": "set FCM TOKEN first"}
    response = requests.post(
        "https://securenet-notif.onrender.com/notif",
        json={'fcmToken': fcmToken, 'title': title, 'body': body},
        headers={"Content-Type": "application/json"}
    )
    return response.json()

import joblib
import numpy as np
import pickle

@app.post("/dynamic/ipdom")
async def ip_or_domain_report(package: str, port: int | None = None, ip: str | None = None, domain: str | None = None):
    # type = "ip"
    if ip:
        source_ip = "192.168.100.103"

        in_data = []

        source_ip = source_ip.split('.')
        source_ip = [in_data.append(float(i)) for i in source_ip]

        in_data.append(float(port))

        des_ip = ip.split('.')
        des_ip = [in_data.append(float(i)) for i in des_ip]

        in_data.append(float(port))

        in_features = [0.000e+00, 0.000e+00, 3.000e+00, 1.800e+02, 0.000e+00, 0.000e+00, 1.000e+00, 1.000e+00]

        [in_data.append(i) for i in in_features] 

        in_data = np.array(in_data).reshape(1, -1)

        with open('model.pkl', 'rb') as f:
            model = pickle.load(f)

        prediction = model.predict(in_data)

        print(prediction)


        # Check if the IP is already present in the Redis cache
        ip_report_redis = check_ip_report(ip)
        if ip_report_redis:
            print("IP Check: Cache Hit!")
            return json.loads(ip_report_redis)
        else:
            print("IP Check: No Cache Found!")
            # Fetch the IP report from ipdata.co
            ip_report_data = ip_report(ip)

            # Store the IP report in the Redis cache
            add_ip_report(ip, port, package, json.dumps(ip_report_data))
            return ip_report_data
    elif domain:
        # type = "domain"
        # Check if the domain is already present in the Redis cache
        domain_report_redis = check_domain_report(domain)
        if domain_report_redis:
            print("Domain Check: Cache Hit!")
            return json.loads(domain_report_redis)
        else:
            print("Domain Check: No Cache Found!")
            # Fetch the domain report from ipdata.co
            domain_report_data = domain_report(domain)

            # Store the domain report in the Redis cache
            add_domain_report(domain, package, json.dumps(domain_report_data))
            return domain_report_data
    else:
        raise HTTPException(
            status_code=500, detail="Incorrect Parameters Provided")

@app.post("/dynamic/url_report")
async def url_report(package: str, url: str):
    try:
        response = requests.get(f"https://www.ipqualityscore.com/api/json/url/{os.environ['IPQUALITYSCORE_API_KEY']}/{urllib.parse.quote(url, safe='')}")
        response = response.json()
        response['package'] = package
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
