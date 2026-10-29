"""Check actual migration indexes and the retention selectors used by the Worker."""
import pathlib
import re
import sqlite3
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class QueryPlans(unittest.TestCase):
    def test_retention_uses_indexes(self):
        with sqlite3.connect(':memory:') as db:
            for migration in sorted((ROOT / 'migrations').glob('*.sql')):
                db.executescript(migration.read_text())
            selectors = re.findall(r'SELECT (?:blob_key|rowid) FROM (?:blob_objects|action_results|action_manifests) WHERE [^"\n]+?LIMIT 200', (ROOT / 'src/maintenance.rs').read_text())
            self.assertEqual(len(selectors), 4)
            for sql in selectors:
                plan = str(db.execute('EXPLAIN QUERY PLAN ' + sql, (1000,)).fetchall())
                self.assertIn('COVERING INDEX', plan)
                self.assertNotIn('TEMP B-TREE', plan)
            plan = str(db.execute('EXPLAIN QUERY PLAN DELETE FROM namespace_blobs WHERE blob_key=?', ('key',)).fetchall())
            self.assertIn('idx_namespace_blobs_blob_key', plan)

if __name__ == '__main__':
    unittest.main()
