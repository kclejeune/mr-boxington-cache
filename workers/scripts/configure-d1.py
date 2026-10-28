#!/usr/bin/env python3
"""Enable automatic read replication with the logged-in Wrangler account."""
import argparse
import json
import pathlib
import subprocess
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=pathlib.Path, default=ROOT / 'wrangler.local.jsonc')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    account = config['account_id']
    database = next(db['database_id'] for db in config['d1_databases'] if db['binding'] == 'MBX_DB')
    # Use Wrangler's credential interface; never print or persist the OAuth token.
    auth = json.loads(subprocess.check_output([
        'node', str(ROOT / 'node_modules/wrangler/bin/wrangler.js'),
        'auth', 'token', '--json',
    ], cwd=ROOT, text=True))
    request = urllib.request.Request(
        f'https://api.cloudflare.com/client/v4/accounts/{account}/d1/database/{database}',
        method='PUT', data=json.dumps({'read_replication': {'mode': 'auto'}}).encode(),
        headers={'Authorization': 'Bearer ' + auth['token'], 'Content-Type': 'application/json'},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        result = json.load(response)
    if not result['success'] or result['result']['read_replication']['mode'] != 'auto':
        raise SystemExit('Cloudflare did not enable D1 read replication')
    print(json.dumps({'database_id': database, 'read_replication': result['result']['read_replication']}))


if __name__ == '__main__':
    main()
