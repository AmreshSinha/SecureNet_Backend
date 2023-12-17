import requests
import os
from dotenv import load_dotenv

load_dotenv()


def ip_report(ip: str):
    response = requests.get(
        f"https://api.ipdata.co/{ip}/threat?api-key={os.environ['IPDATA_API_KEY']}")
    return response.json()