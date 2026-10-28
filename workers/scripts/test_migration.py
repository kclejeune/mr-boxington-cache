"""SQLite exercises the Rust planner's actual SQL, including replay and D1-side edits."""
import copy
import json
import os
import pathlib
import sqlite3
import subprocess
import tempfile
import unittest

WORKERS = pathlib.Path(__file__).resolve().parents[1]
PLANNER = pathlib.Path(os.environ.get('MBX_MIGRATION_PLANNER', WORKERS.parent / 'target/debug/mbx-cache-migrate'))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(value):
    encoded = value.encode()
    hashed = subprocess.check_output(['node', '--input-type=module', '-e',
        "import {blake3} from '@noble/hashes/blake3.js';import{readFileSync}from'node:fs';process.stdout.write(Buffer.from(blake3(readFileSync(0))).toString('hex'));"], input=encoded, cwd=WORKERS).decode()
    return {'algorithm': 'blake3', 'hash': hashed, 'size': len(encoded)}


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.execute('PRAGMA foreign_keys=ON')
        for schema in sorted((WORKERS / 'migrations').glob('*.sql')):
            self.db.executescript(schema.read_text())
        self.blob = {'algorithm': 'blake3', 'hash': 'a' * 64, 'size': 3}
        self.blob_key = 'blake3/' + 'a' * 64 + '/3'
        task = 'b' * 64
        self.selector = digest(canonical({'kind': 'task_action_manifest', 'task': task, 'version': 1}))
        self.manifest = {'version': 1, 'task': task, 'predictions': []}
        self.key = f'blake3/{self.selector["hash"]}/{self.selector["size"]}'
        self.snapshot = [
            {'kind': 'snapshot', 'source': 'gateway/test', 'snapshot_at': 3_000_000},
            *[{'kind': 'blob', 'namespace': n, 'digest': self.blob, 'created_at': 100} for n in ['one', 'two']],
            {'kind': 'action', 'namespace': 'one', 'digest': self.blob,
             'result': {'action': self.blob, 'metadata': None, 'output_root': None, 'version': 1}, 'created_at': 100},
            self.manifest_record(1_000_000), {'kind': 'end'},
        ]
        self.inventory = [
            {'kind': 'inventory', 'bucket': 'existing', 'prefix': 'native/v1/blobs/'},
            {'kind': 'object', 'key': 'native/v1/blobs/' + self.blob_key, 'size': 3, 'created_at': 99},
            {'kind': 'inventory_end', 'pages': 1},
        ]
        self.index = 0

    def manifest_record(self, version):
        return {'kind': 'manifest', 'namespace': 'one', 'digest': self.selector,
                'etag': digest(canonical(self.manifest))['hash'], 'manifest': copy.deepcopy(self.manifest), 'updated_at': version}

    def generate(self):
        self.index += 1
        snapshot = self.directory / f'{self.index}.snapshot'
        inventory = self.directory / f'{self.index}.inventory'
        out = self.directory / str(self.index)
        snapshot.write_text(''.join(json.dumps(row) + '\n' for row in self.snapshot))
        inventory.write_text(''.join(json.dumps(row) + '\n' for row in self.inventory))
        subprocess.run([str(PLANNER), '--snapshot', str(snapshot), '--inventory', str(inventory), '--output', str(out)], check=True, stdout=subprocess.DEVNULL)
        plan = json.loads((out / 'plan.json').read_text())
        return out, plan

    def apply(self):
        out, plan = self.generate()
        for file in plan['sql_files']:
            self.db.executescript((out / file).read_text())
        return plan

    def source_advance(self, at):
        self.manifest['predictions'] = [{'action': self.blob, 'invocation': self.blob, 'adapter': 'task', 'payload': json.dumps({'version': at})}]
        self.snapshot[-2] = self.manifest_record(at)

    def test_replay_is_idempotent_and_references_original_keys(self):
        plan = self.apply()
        changes = self.db.total_changes
        self.apply()
        self.assertEqual(changes, self.db.total_changes)
        self.assertEqual(self.db.execute('SELECT object_key,created_at FROM blob_objects').fetchone(), ('native/v1/blobs/' + self.blob_key, 99))
        self.assertEqual(self.db.execute('SELECT count(*) FROM namespace_blobs').fetchone()[0], 2)
        self.assertEqual(plan['counts']['unique_blobs'], 1)

    def test_new_source_manifests_advance_but_old_snapshots_do_not_roll_them_back(self):
        self.apply()
        old = copy.deepcopy(self.snapshot)
        self.source_advance(2_000_000)
        self.apply()
        expected = self.snapshot[-2]['etag']
        self.snapshot = old
        self.apply()
        self.assertEqual(self.db.execute('SELECT etag FROM action_manifests').fetchone()[0], expected)
        self.assertEqual(self.db.execute('SELECT source_updated_at FROM postgres_manifest_imports').fetchone()[0], 2_000_000)

    def test_worker_manifest_edits_are_preserved_and_reported(self):
        self.apply()
        self.db.execute("UPDATE action_manifests SET etag=?,object_key='workers/v1/edited'", ('f' * 64,))
        self.source_advance(2_000_000)
        self.apply()
        self.assertEqual(self.db.execute('SELECT etag FROM action_manifests').fetchone()[0], 'f' * 64)
        self.assertEqual(self.db.execute("SELECT count(*) FROM postgres_import_conflicts WHERE kind='manifest'").fetchone()[0], 1)

    def test_immutable_action_conflicts_preserve_the_target(self):
        self.apply()
        self.db.execute("UPDATE action_results SET result=json_set(result,'$.version',2)")
        self.apply()
        self.assertEqual(self.db.execute("SELECT json_extract(result,'$.version') FROM action_results").fetchone()[0], 2)
        self.assertEqual(self.db.execute("SELECT count(*) FROM postgres_import_conflicts WHERE kind='action'").fetchone()[0], 1)

    def test_missing_objects_are_not_published(self):
        self.inventory.pop(1)
        plan = self.apply()
        self.assertEqual(plan['counts']['missing_blobs'], 1)
        self.assertEqual(plan['counts']['skipped_actions'], 1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM blob_objects').fetchone()[0], 0)

    def test_incomplete_exports_are_rejected_before_sql_is_applied(self):
        self.snapshot.pop()
        with self.assertRaises(subprocess.CalledProcessError):
            self.generate()
        self.assertEqual(self.db.total_changes, 0)


if __name__ == '__main__':
    unittest.main()
