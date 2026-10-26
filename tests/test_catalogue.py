"""The catalogue is valid, consistent and documented."""

from __future__ import annotations

import copy
import json
import os
import unittest

from macaudit import catalogue as cat
from macaudit import render
from tests.helpers import ROOT, catalogue, jsonschema, load_json


class CatalogueTest(unittest.TestCase):
    def test_loads_and_sizes(self) -> None:
        c = catalogue()
        self.assertGreaterEqual(len(c.checks), 25)
        self.assertLessEqual(len(c.checks), 40)
        used = {check.area for check in c.checks}
        self.assertEqual(used, set(c.areas), "every area has checks and every check has an area")

    def test_line_numbers_point_at_the_id(self) -> None:
        c = catalogue()
        with open(cat.CATALOGUE_PATH, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        for check in c.checks:
            self.assertIn(f'"{check.id}"', lines[check.line - 1])

    def test_rejects_duplicate_ids(self) -> None:
        data = load_json(cat.CATALOGUE_PATH)
        data["checks"].append(copy.deepcopy(data["checks"][0]))
        with self.assertRaises(cat.CatalogueError):
            cat.parse(data)

    def test_rejects_unknown_builtin_and_bad_regex(self) -> None:
        data = load_json(cat.CATALOGUE_PATH)
        broken = copy.deepcopy(data)
        broken["checks"][0]["probe"] = {"type": "builtin", "name": "does_not_exist"}
        with self.assertRaises(cat.CatalogueError):
            cat.parse(broken)
        broken = copy.deepcopy(data)
        broken["checks"][0]["evaluate"][0]["pattern"] = "("
        with self.assertRaises(cat.CatalogueError):
            cat.parse(broken)

    def test_remediation_is_text_only(self) -> None:
        # macaudit never applies a fix, so the catalogue has no field that could hold one.
        data = load_json(cat.CATALOGUE_PATH)
        for raw in data["checks"]:
            self.assertNotIn("fix", raw)
            self.assertNotIn("apply", raw)
            for step in raw["remediation"]:
                self.assertIsInstance(step, str)

    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_catalogue_matches_its_schema(self) -> None:
        assert jsonschema is not None
        schema = load_json(os.path.join(cat.DATA_DIR, "catalogue.schema.json"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(load_json(cat.CATALOGUE_PATH), schema, cls=jsonschema.Draft202012Validator)

    def test_docs_catalogue_is_up_to_date(self) -> None:
        with open(os.path.join(ROOT, "docs", "checks.md"), encoding="utf-8") as handle:
            on_disk = handle.read()
        self.assertEqual(
            on_disk,
            render.catalogue_markdown(catalogue()),
            "docs/checks.md is stale. Run: python3 -m macaudit list --format markdown > docs/checks.md",
        )

    def test_catalogue_json_listing(self) -> None:
        rows = json.loads(render.catalogue_json(catalogue()))
        self.assertEqual(len(rows), len(catalogue().checks))


if __name__ == "__main__":
    unittest.main()
