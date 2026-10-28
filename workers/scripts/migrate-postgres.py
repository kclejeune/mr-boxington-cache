#!/usr/bin/env python3
"""Repeatable PostgreSQL -> D1 import using SSH, a Rust planner, and Wrangler.

By default only exports and prepares a plan. --apply uploads manifest bodies and
imports SQL. It never modifies PostgreSQL, existing R2 blobs, or client routing.
"""
import argparse
import json
import os
import pathlib
import shlex
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO = ROOT.parent


def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def export_sql(source):
    source = "'" + source.replace("'", "''") + "'"
    digest = "json_build_object('algorithm',algorithm,'hash',hash,'size',size)"
    return f"""
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT json_build_object('kind','snapshot','source',{source},'snapshot_at',(extract(epoch FROM transaction_timestamp())*1000000)::bigint);
SELECT json_build_object('kind','blob','namespace',namespace,'digest',{digest},'created_at',floor(extract(epoch FROM created_at))::bigint) FROM namespace_blobs ORDER BY namespace,algorithm,hash,size;
SELECT json_build_object('kind','action','namespace',namespace,'digest',{digest},'result',result,'created_at',floor(extract(epoch FROM created_at))::bigint) FROM action_results ORDER BY namespace,algorithm,hash,size;
SELECT json_build_object('kind','manifest','namespace',namespace,'digest',{digest},'etag',etag,'manifest',manifest,'updated_at',(extract(epoch FROM updated_at)*1000000)::bigint) FROM action_manifests ORDER BY namespace,algorithm,hash,size;
SELECT json_build_object('kind','end');
COMMIT;
""".encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='gateway')
    parser.add_argument('--database', default='mbx_cache')
    parser.add_argument('--service', default='mbx-cache')
    parser.add_argument('--config', default='wrangler.local.jsonc')
    parser.add_argument('--source', help='stable source ID; defaults to HOST/DATABASE')
    parser.add_argument('--output', type=pathlib.Path, help='new private directory for snapshots and the generated plan')
    parser.add_argument('--snapshot', type=pathlib.Path, help='reuse a previous complete NDJSON snapshot')
    parser.add_argument('--inventory', type=pathlib.Path, help='reuse a previous complete NDJSON R2 inventory')
    parser.add_argument('--planner', type=pathlib.Path, default=REPO / 'target/debug/mbx-cache-migrate')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    output = (args.output or pathlib.Path(tempfile.mkdtemp(prefix='mbx-postgres-import-'))).resolve()
    if (output / 'plan').exists():
        raise SystemExit('output already contains a plan; use a fresh --output directory')
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    snapshot = args.snapshot.resolve() if args.snapshot else output / 'postgres.ndjson'
    inventory = args.inventory.resolve() if args.inventory else output / 'r2.ndjson'
    config_path = pathlib.Path(args.config)
    if not config_path.is_absolute():
        config_path = ROOT / config_path
    # Instance config is plain JSON; the repository's JSONC template must be copied first.
    config = json.loads(config_path.read_text())
    if config.get('vars', {}).get('MBX_CACHE_CLEANUP_ENABLED', 'false') != 'false':
        raise SystemExit('disable Worker cleanup in the deployment config before importing')
    prefix = config.get('vars', {}).get('MBX_CACHE_R2_PREFIX', 'workers/v1')
    if not args.snapshot:
        print('Exporting a read-only repeatable-read PostgreSQL snapshot...', flush=True)
        remote = shlex.join(['sudo', '-n', '-u', 'postgres', 'psql', '-XqAt', '-v', 'ON_ERROR_STOP=1', '-d', args.database])
        with snapshot.open('wb') as destination:
            run(['ssh', '-o', 'BatchMode=yes', args.host, remote], input=export_sql(args.source or f'{args.host}/{args.database}'), stdout=destination)
    if not args.inventory:
        print('Listing source R2 objects without copying blob contents...', flush=True)
        script = (ROOT / 'scripts/source-objects.py').read_bytes()
        with inventory.open('wb') as destination:
            run(['ssh', '-o', 'BatchMode=yes', args.host, shlex.join(['sudo', '-n', 'python3', '-', args.service])], input=script, stdout=destination)
    plan_dir = output / 'plan'
    run([str(args.planner), '--snapshot', str(snapshot), '--inventory', str(inventory), '--output', str(plan_dir), '--worker-prefix', prefix])
    plan = json.loads((plan_dir / 'plan.json').read_text())
    buckets = {entry['binding']: entry['bucket_name'] for entry in config['r2_buckets']}
    if buckets.get('MBX_BLOBS') != plan['bucket']:
        raise SystemExit('source and destination bucket names differ; refusing import')
    print(f'Plan saved in {plan_dir}', flush=True)
    if not args.apply:
        print('No Cloudflare data was modified. Rerun with --apply and a fresh output directory to import.')
        return
    wrangler = ['node', str(ROOT / 'node_modules/wrangler/bin/wrangler.js')]
    env = os.environ | {'WRANGLER_LOG_PATH': '/tmp/mbx-wrangler-migration.log', 'WRANGLER_SEND_METRICS': 'false'}
    def wr(*command):
        return run([*wrangler, *command, '--config', str(config_path)], cwd=ROOT, env=env)
    # Complete the schema before any data publication. Both migrations are additive.
    wr('d1', 'migrations', 'apply', 'MBX_DB', '--remote')
    # Every pointer published by the SQL import must already have a body.
    for manifest in plan['manifests']:
        print(f'Uploading manifest {manifest["file"]}', flush=True)
        wr('r2', 'object', 'put', f'{plan["bucket"]}/{manifest["key"]}', '--file', str(plan_dir / manifest['file']), '--remote')
    for index, sql_file in enumerate(plan['sql_files']):
        print(f'Importing SQL page {index+1}/{len(plan["sql_files"])}', flush=True)
        wr('d1', 'execute', 'MBX_DB', '--remote', '--file', str(plan_dir / sql_file), '--yes')
    wr('d1', 'execute', 'MBX_DB', '--remote', '--command', "SELECT 'blobs' AS kind,count(*) AS rows FROM blob_objects UNION ALL SELECT 'memberships',count(*) FROM namespace_blobs UNION ALL SELECT 'actions',count(*) FROM action_results UNION ALL SELECT 'manifests',count(*) FROM action_manifests UNION ALL SELECT 'conflicts',count(*) FROM postgres_import_conflicts")
    print(f'Import complete. Audit snapshots and plan retained privately in {output}', flush=True)


if __name__ == '__main__':
    main()
