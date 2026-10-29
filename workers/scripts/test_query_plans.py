"""Check the actual Worker SQL against the migrated schema."""
import json
import pathlib
import re
import sqlite3
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class QueryPlans(unittest.TestCase):
    def test_bulk_queries_use_full_key_lookups(self):
        source = (ROOT / 'src/metadata.rs').read_text()
        # Read Rust string literals, including backslash-continued SQL, so changes
        # to the production queries cannot leave a separately copied test green.
        literals = re.findall(r'"((?:[^"\\]|\\.)*)"', source, re.S)
        selectors = [re.sub(r'\\\n\s*', '', sql) for sql in literals
                     if sql.startswith('SELECT ') and 'json_each(' in sql]
        self.assertEqual(len(selectors), 6)
        with sqlite3.connect(':memory:') as db:
            for migration in sorted((ROOT / 'migrations').glob('*.sql')):
                db.executescript(migration.read_text())
            for sql in selectors:
                args = ('ns', '["key"]') if '?2' in sql else (
                    json.dumps([{'blob': 'key', 'object': 'object'}]),)
                with self.subTest(sql=sql):
                    plan = [row[3] for row in db.execute('EXPLAIN QUERY PLAN ' + sql, args)]
                    self.assertRegex(plan[0], r'SCAN (requested|r) VIRTUAL TABLE')
                    for step in plan[1:]:
                        self.assertIn('SEARCH ', step)
                        if 'namespace_blobs' in sql and re.search(r'SEARCH (b|blobs) ', step):
                            self.assertIn('(namespace=? AND blob_key=?)', step)
                        elif 'action_results' in sql:
                            self.assertIn('(namespace=? AND action_key=?)', step)
                        else:
                            self.assertIn('(blob_key=?)', step)
                    self.assertNotIn('TEMP B-TREE', str(plan))

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
