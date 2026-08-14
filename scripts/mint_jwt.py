"""문서 추출용 HS256 토큰을 만든다.

auth의 /v3/api-docs는 authenticated()에 걸린다. auth는 JWT_SECRET으로 서명을
검증하는데(NimbusJwtDecoder.withSecretKey, HS256), 그 시크릿을 CI가 정하므로
CI가 직접 서명한 토큰은 유효하다. exp는 필수다(JwtConfig가 빈 exp를 거부한다).
"""
import base64
import hashlib
import hmac
import json
import os
import time


def b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


secret = os.environ["JWT_SECRET"].encode()
header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"sub": "0", "exp": int(time.time()) + 3600}).encode())
signature = b64url(hmac.new(secret, header + b"." + payload, hashlib.sha256).digest())
print((header + b"." + payload + b"." + signature).decode())
