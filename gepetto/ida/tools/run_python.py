import io
import json
import traceback
from contextlib import redirect_stdout, redirect_stderr

from gepetto.ida.tools.tools import (
    add_result_to_messages,
    tool_error_payload,
    tool_result_payload,
)


def handle_run_python_tc(tc, messages):
    """
    Tool: run_python
    Args (JSON):
      - code: str (required)

    Returns (success):
      - stdout: str
      - stderr: str

    Returns (error):
      - traceback: str
    """
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}

    code = args.get("code")

    try:
        if not isinstance(code, str) or not code.strip():
            raise ValueError("code must be a non-empty string")

        payload = tool_result_payload(run_python(code))
    except Exception:
        payload = tool_error_payload(
            traceback.format_exc(),
            code=code,
        )

    add_result_to_messages(messages, tc, payload)


def run_python(code: str) -> dict:
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    env = {"__builtins__": __builtins__}

    try:
        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            exec(code, env, env)  # intentional arbitrary execution

        return {
            "stdout": stdout_buf.getvalue(),
            "stderr": stderr_buf.getvalue(),
        }
    except Exception:
        # Always return traceback, never structured exception info
        raise RuntimeError(traceback.format_exc())
