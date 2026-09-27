import json
from pathlib import Path
import tempfile
import unittest

from native_tool_trace import ToolTrace, tool_names


class TracePrivacyTest(unittest.TestCase):
    def test_only_tool_names_and_types_are_retained(self):
        secret = "sensitive synthetic prompt and credential"
        tools = [{"type": "namespace", "name": "cicada", "description": secret, "tools": [
            {"type": "function", "name": "cicada_join", "parameters": {"secret": secret}}]}]
        self.assertEqual(tool_names(tools), [{"type": "namespace", "name": "cicada", "tools": [
            {"type": "function", "name": "cicada_join"}]}])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            trace = ToolTrace(path)
            trace.response_event(1, json.dumps({"type": "response.output_item.done", "item": {
                "type": "function_call", "name": "cicada_join", "arguments": secret, "output": secret}}).encode())
            trace.response_event(1, json.dumps({"type": "error", "message": secret}).encode())
            trace.server.server_close()
            self.assertNotIn(secret, path.read_text())
            self.assertIn("cicada_join", path.read_text())


if __name__ == "__main__":
    unittest.main()
