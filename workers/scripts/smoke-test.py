#!/usr/bin/env python3
"""Publish small fixtures and require real edge hits on a deployed Worker."""
import argparse
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--namespace', required=True)
    args = parser.parse_args()
    token = os.environ['MBX_REMOTE_TOKEN']
    # urllib's default user agent can be blocked by Cloudflare's bot filters.
    headers = {'mbx-cache-protocol': '1', 'mbx-cache-namespace': args.namespace,
               'Authorization': 'Bearer ' + token, 'User-Agent': 'mbx-worker-smoke/1'}

    def request(path, method='GET', body=None, extra=None):
        req = urllib.request.Request(args.url.rstrip('/') + path, method=method,
                                     data=body, headers=headers | (extra or {}))
        try:
            response = urllib.request.urlopen(req, timeout=60)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.headers, response.read()

    def encode(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

    def digest(body):
        return {'algorithm': 'sha256', 'hash': hashlib.sha256(body).hexdigest(), 'size': len(body)}

    def path(kind, d):
        return f'/v1/{kind}/{d["algorithm"]}/{d["hash"]}/{d["size"]}'

    def put(body):
        d = digest(body)
        status, _, response = request(path('blobs', d), 'PUT', body, {'If-None-Match': '*'})
        assert status in (201, 204), (status, response)
        return d

    def hit(url, expected):
        statuses = []
        for attempt in range(10):
            status, response_headers, body = request(url)
            # A just-published record can briefly be absent from an unconstrained replica.
            if status == 404:
                time.sleep(0.25)
                continue
            assert status == 200, (status, body)
            assert (json.loads(body) if isinstance(expected, dict) else body) == expected, 'cached body mismatch'
            assert response_headers.get('cache-control') == 'private, no-store'
            statuses.append(response_headers.get('mbx-cache-edge-status'))
            if statuses[-1] == 'HIT':
                print(json.dumps({'resource': url.split('/')[2], 'cache_statuses': statuses}))
                return
            time.sleep(0.25)
        raise AssertionError(f'no real Workers Cache HIT: {statuses}')

    body = ('mbx-workers-smoke-' + uuid.uuid4().hex).encode()
    d = digest(body)
    url = path('blobs', d)
    assert request(url)[0] == 404  # Negative reads must not survive publication.
    put(body)
    hit(url, body)
    assert request(url, extra={'Authorization': 'Bearer invalid-smoke-token'})[0] == 401
    assert request(url, extra={'mbx-cache-namespace': args.namespace + '-cache-probe'})[0] in (403, 404)
    status, head, head_body = request(url, 'HEAD')
    assert status == 200 and not head_body
    assert head.get('mbx-cache-edge-status') == 'HIT'
    status, _, packed = request('/v1/blobs:pack', 'POST', encode({'digests': [d]}))
    expected_pack = b'MBXPACK1' + b'\x02' + bytes.fromhex(d['hash']) + d['size'].to_bytes(8, 'big') + body
    assert status == 200 and packed == expected_pack

    action_body = encode({'arch': 'x86_64', 'args': [], 'command_inputs': [], 'dependency_keys': [],
                         'environment': {}, 'kind': 'task', 'os': 'linux', 'outputs': [],
                         'phase': 'normal', 'root': '.', 'run': ['true'], 'shell': None,
                         'source_hash': uuid.uuid4().hex, 'task': 'worker-smoke', 'tools': [],
                         'vars': {}, 'version': 1})
    action = put(action_body)
    result = {'action': action, 'metadata': None, 'output_root': None, 'version': 1}
    result_url = path('action-results', action)
    status, _, response = request(result_url, 'PUT', encode(result), {'If-None-Match': '*'})
    assert status in (201, 204), (status, response)
    hit(result_url, result)
    status, _, batch = request('/v1/action-results:batch', 'POST', encode({'digests': [action]}))
    assert status == 200 and json.loads(batch) == {'results': [result]}
    print('Deployed Worker smoke passed: blobs, actions, packs, batches, HEAD, auth, edge HITs.')


if __name__ == '__main__':
    main()
