#!/usr/bin/env python3
"""Run on the native host via sudo. Use its running service's S3 credentials.

Only object metadata is written to stdout; credentials never leave this process.
"""
import datetime
import hashlib
import hmac
import json
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

service = sys.argv[1] if len(sys.argv) > 1 else 'mbx-cache'
pid = subprocess.check_output(['systemctl', 'show', service, '-p', 'MainPID', '--value'], text=True).strip()
env = dict(item.split('=', 1) for item in pathlib.Path(f'/proc/{pid}/environ').read_text().split('\0') if '=' in item)
if env.get('MBX_CACHE_STORAGE') != 's3':
    raise SystemExit('source service must use S3-compatible storage')
endpoint = env['MBX_CACHE_S3_ENDPOINT'].rstrip('/')
bucket = env['MBX_CACHE_S3_BUCKET']
prefix = env.get('MBX_CACHE_S3_PREFIX', 'v1').strip('/') + '/blobs/'
region = env.get('MBX_CACHE_S3_REGION', 'auto')
access = env['AWS_ACCESS_KEY_ID']
secret = env['AWS_SECRET_ACCESS_KEY']


def sign(key, message):
    return hmac.new(key, message.encode(), hashlib.sha256).digest()


def page(token):
    query = {'list-type': '2', 'max-keys': '1000', 'prefix': prefix}
    if token:
        query['continuation-token'] = token
    query = '&'.join(urllib.parse.quote(k, safe='~') + '=' + urllib.parse.quote(v, safe='~') for k, v in sorted(query.items()))
    url = endpoint + '/' + urllib.parse.quote(bucket, safe='~')
    parsed = urllib.parse.urlsplit(url)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    date = stamp[:8]
    scope = f'{date}/{region}/s3/aws4_request'
    payload = hashlib.sha256(b'').hexdigest()
    headers = {'host': parsed.netloc, 'x-amz-content-sha256': payload, 'x-amz-date': stamp}
    if env.get('AWS_SESSION_TOKEN'):
        headers['x-amz-security-token'] = env['AWS_SESSION_TOKEN']
    names = ';'.join(sorted(headers))
    canonical = '\n'.join(['GET', parsed.path, query, ''.join(k + ':' + headers[k] + '\n' for k in sorted(headers)), names, payload])
    string_to_sign = '\n'.join(['AWS4-HMAC-SHA256', stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = sign(sign(sign(sign(('AWS4' + secret).encode(), date), region), 's3'), 'aws4_request')
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    headers['Authorization'] = f'AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={names}, Signature={signature}'
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url + '?' + query, headers=headers), timeout=60) as response:
                return ET.fromstring(response.read())
        except (urllib.error.URLError, TimeoutError):
            if attempt == 3:
                raise RuntimeError('S3 inventory request failed (credentials redacted)') from None
            time.sleep(2 ** attempt)


print(json.dumps({'kind': 'inventory', 'bucket': bucket, 'prefix': prefix}), flush=True)
token = None
pages = 0
while True:
    root = page(token)
    for obj in root.findall('{*}Contents'):
        modified = datetime.datetime.fromisoformat(obj.findtext('{*}LastModified').replace('Z', '+00:00'))
        print(json.dumps({'kind': 'object', 'key': obj.findtext('{*}Key'), 'size': int(obj.findtext('{*}Size')), 'created_at': int(modified.timestamp())}))
    pages += 1
    if pages % 10 == 0:
        print(f'Listed {pages} S3 pages', file=sys.stderr)
    if root.findtext('{*}IsTruncated') != 'true':
        break
    token = root.findtext('{*}NextContinuationToken')
    if not token:
        raise SystemExit('S3 returned a truncated page without a continuation token')
print(json.dumps({'kind': 'inventory_end', 'pages': pages}), flush=True)
