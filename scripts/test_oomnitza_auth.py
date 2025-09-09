import os
import sys
import requests


def main():
    url = (os.getenv("OOMNITZA_URL") or "").rstrip('/')
    token = os.getenv("OOMNITZA_API_TOKEN")
    verify_env = os.getenv("OOMNITZA_VERIFY_SSL") or os.getenv("VERIFY_SSL")
    verify = True if verify_env is None else str(verify_env).lower() in ("1", "true", "yes", "y")

    if not url or not token:
        print("Missing OOMNITZA_URL or OOMNITZA_API_TOKEN in environment.")
        return 2

    try:
        headers = {
            "Authorization2": token,
            "Accept": "application/json",
        }
        resp = requests.get(f"{url}/api/v2/mappings?name=AuthTest", headers=headers, timeout=20, verify=verify)
        if resp.status_code == 200:
            print("Oomnitza auth OK")
            return 0
        else:
            print(f"Oomnitza auth failed: {resp.status_code} {resp.text[:200]}")
            return 1
    except requests.RequestException as e:
        print(f"Oomnitza auth error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
