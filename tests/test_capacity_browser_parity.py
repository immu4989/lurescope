"""The local browser panel must reproduce the Python CLI's scenario contract."""

import json
import random
import shutil
import subprocess
from pathlib import Path

import pytest

from lurescope.capacity import COUNT_FIELDS, plan_capacity


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is optional outside browser CI")
def test_browser_matches_python_for_generated_valid_scenarios():
    rng = random.Random(4989)
    cases = []
    for _ in range(80):
        validation = dict(schema_version=1, task="fraud", detector="synthetic-parity", threshold=.5,
                          counts={key: rng.randrange(1, 1000) for key in sorted(COUNT_FIELDS)})
        options = dict(messages_per_period=rng.randrange(1, 1_000_000),
                       prevalences=[0., .0001, .001, .01, .1, .5, 1.],
                       review_minutes_per_case=rng.randrange(1, 100),
                       available_review_hours=rng.randrange(0, 10000))
        cases.append(dict(validation=validation, options=options))
    module = Path(__file__).parents[1] / "lurescope/static/capacity-planner.js"
    script = (
        'const fs = require("node:fs"); const {plan} = require(process.argv[1]);'
        'const cases = JSON.parse(fs.readFileSync(0, "utf8"));'
        'process.stdout.write(JSON.stringify(cases.map(c => plan(c.validation, c.options))));'
    )
    completed = subprocess.run([shutil.which("node"), "-e", script, str(module)],
                               input=json.dumps(cases), text=True, capture_output=True,
                               check=True, timeout=20)
    expected = [plan_capacity(case["validation"], **case["options"]) for case in cases]
    assert json.loads(completed.stdout) == expected
