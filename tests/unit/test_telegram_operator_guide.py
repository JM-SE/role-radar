import ast
import re
from pathlib import Path

import pytest

GUIDE = Path("docs/integrations/telegram.md").read_text()
SNIPPET = re.search(r"```sh\n.*?<<'PY'\n(.*?)\nPY\n```", GUIDE, re.S)[1]
TREE = ast.parse(SNIPPET)


def helper(name):
    node = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name)
    module = ast.Module(body=[node], type_ignores=[])
    namespace = {
        "re": re,
        "MARKER": "/start role-radar-setup",
        "stop": lambda reason: (_ for _ in ()).throw(ValueError(reason)),
    }
    namespace["urllib"] = __import__("urllib", fromlist=["error"])
    exec(compile(module, "telegram-guide", "exec"), namespace)
    return namespace[name]


def test_token_parser_accepts_single_line_literal_assignment():
    parse = helper("token_from_env")
    assert parse('OTHER=value\nROLE_RADAR_TELEGRAM_BOT_TOKEN="123:abc"\n') == "123:abc"


@pytest.mark.parametrize(
    "text",
    [
        'OTHER="multiline\nROLE_RADAR_TELEGRAM_BOT_TOKEN=123:secret\nend"\n',
        "ROLE_RADAR_TELEGRAM_BOT_TOKEN=123:abc\\\nNEXT=value\n",
        "ROLE_RADAR_TELEGRAM_BOT_TOKEN=123:abc\nROLE_RADAR_TELEGRAM_BOT_TOKEN=456:def\n",
        "OTHER=$(command)\nROLE_RADAR_TELEGRAM_BOT_TOKEN=123:abc\n",
    ],
)
def test_token_parser_fails_closed_on_unsupported_or_ambiguous_syntax(text):
    with pytest.raises(ValueError):
        helper("token_from_env")(text)


def test_private_exact_marker_selection_gates_remain():
    chat_ids = helper("chat_ids")
    marker = "/start role-radar-setup"
    assert chat_ids([{"message": {"chat": {"type": "private", "id": 7}, "text": marker}}]) == [7]
    assert chat_ids(
        [
            {"message": {"chat": {"type": "group", "id": 8}, "text": marker}},
            {"message": {"chat": {"type": "private", "id": 9}, "text": "/start other"}},
        ]
    ) == []


def test_error_message_never_echoes_runtime_error():
    error_message = helper("error_message")
    error = RuntimeError("https://example.test/botSECRET tokenSECRET")
    assert error_message(error) == "safe lookup failed"


def test_error_message_keeps_fixed_409_stop_without_echoing_exception():
    import urllib.error

    error_message = helper("error_message")
    error = urllib.error.HTTPError("https://secret.invalid/token", 409, "secret", {}, None)
    assert error_message(error) == "Telegram HTTP 409; stop, do not delete webhook"


def test_embedded_operator_snippet_is_valid_python():
    compile(SNIPPET, "telegram-guide", "exec")
