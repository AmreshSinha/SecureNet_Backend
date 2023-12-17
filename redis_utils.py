import redis
import json

redis_client = redis.Redis(host='localhost', port='6379', db=0)


def check_ip_report(ip: str):
    key = f"{ip}"
    return redis_client.get(key)


def add_ip_report(ip: str, port: int, package_name: str, report: str):
    key = f"{ip}"
    json_report = {
        "port": port,
        "package_name": package_name,
        "report": json.loads(report)
    }
    redis_client.set(key, json.dumps(json_report))
    redis_client.expire(key, 60 * 60 * 24 * 7)  # Expire after 7 days


def check_domain_report(domain: str):
    key = f"{domain}"
    return redis_client.get(key)


def add_domain_report(domain: str, port: str, package_name: str, report: str):
    key = f"{domain}"
    json_report = {
        "port": port,
        "package_name": package_name,
        "report": json.load(report)
    }
    redis_client.set(key, json.dumps(json_report))
    redis_client.expire(key, 60 * 60 * 24 * 7)  # Expire after 7 days
