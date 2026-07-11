from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from netsift.cli import main


class CliTests(unittest.TestCase):
    def test_generate_then_filter_and_summarize(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "demo.pcap"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["generate", str(path)]), 0)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["packets", str(path), "--filter", "proto=dns", "--format", "jsonl"])
            self.assertEqual(code, 0)
            self.assertEqual(len(output.getvalue().strip().splitlines()), 2)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["summary", str(path)]), 0)
            self.assertIn("ENDPOINT A", output.getvalue())

    def test_bad_filter_returns_actionable_exit(self) -> None:
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            code = main(["packets", "missing.pcap", "--filter", "bad"])
        self.assertEqual(code, 2)
        self.assertIn("error", error.getvalue())


if __name__ == "__main__":
    unittest.main()
