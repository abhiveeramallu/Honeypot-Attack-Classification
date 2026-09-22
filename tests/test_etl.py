import json

from etl_parser import load_logs, parse_log_file, to_dataframe


def _write(tmp_path, name, lines):
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(l) if isinstance(l, dict) else l for l in lines) + "\n")
    return path


def test_malformed_json_lines_are_skipped(tmp_path):
    lines = [
        {"eventid": "cowrie.session.connect", "session": "s1", "src_ip": "1.2.3.4", "protocol": "ssh",
         "timestamp": "2026-01-01T00:00:00Z"},
        "{this is not valid json",
        "",  # blank line
        {"eventid": "cowrie.command.input", "input": "whoami", "session": "s1",
         "timestamp": "2026-01-01T00:00:02Z"},
    ]
    path = _write(tmp_path, "cowrie.json", lines)

    sessions = parse_log_file(path)

    assert set(sessions.keys()) == {"s1"}
    assert sessions["s1"].command_sequence == ["whoami"]


def test_events_without_session_id_are_ignored(tmp_path):
    lines = [
        {"eventid": "cowrie.client.version", "version": "SSH-2.0-libssh"},  # no `session` key at all
        {"eventid": "cowrie.session.connect", "session": "s1", "src_ip": "1.2.3.4", "protocol": "ssh",
         "timestamp": "2026-01-01T00:00:00Z"},
    ]
    path = _write(tmp_path, "cowrie.json", lines)

    sessions = parse_log_file(path)

    assert list(sessions.keys()) == ["s1"]


def test_control_characters_and_ansi_escapes_are_stripped(tmp_path):
    lines = [
        {"eventid": "cowrie.session.connect", "session": "s1", "src_ip": "1.2.3.4", "protocol": "ssh",
         "timestamp": "2026-01-01T00:00:00Z"},
        {"eventid": "cowrie.command.input", "input": "\x1b[31mls -la\x1b[0m\x07", "session": "s1",
         "timestamp": "2026-01-01T00:00:01Z"},
    ]
    path = _write(tmp_path, "cowrie.json", lines)

    sessions = parse_log_file(path)

    assert sessions["s1"].command_sequence == ["ls -la"]


def test_duplicate_consecutive_commands_are_deduplicated(tmp_path):
    lines = [
        {"eventid": "cowrie.session.connect", "session": "s1", "src_ip": "1.2.3.4", "protocol": "ssh",
         "timestamp": "2026-01-01T00:00:00Z"},
        {"eventid": "cowrie.command.input", "input": "ls", "session": "s1", "timestamp": "2026-01-01T00:00:01Z"},
        {"eventid": "cowrie.command.input", "input": "ls", "session": "s1", "timestamp": "2026-01-01T00:00:02Z"},
        {"eventid": "cowrie.command.input", "input": "pwd", "session": "s1", "timestamp": "2026-01-01T00:00:03Z"},
        {"eventid": "cowrie.command.input", "input": "ls", "session": "s1", "timestamp": "2026-01-01T00:00:04Z"},
    ]
    path = _write(tmp_path, "cowrie.json", lines)

    sessions = parse_log_file(path)

    # only immediately-repeated duplicates collapse; `ls` reappearing after `pwd` is kept.
    assert sessions["s1"].command_sequence == ["ls", "pwd", "ls"]


def test_empty_command_input_is_dropped(tmp_path):
    lines = [
        {"eventid": "cowrie.session.connect", "session": "s1", "src_ip": "1.2.3.4", "protocol": "ssh",
         "timestamp": "2026-01-01T00:00:00Z"},
        {"eventid": "cowrie.command.input", "input": "   ", "session": "s1", "timestamp": "2026-01-01T00:00:01Z"},
        {"eventid": "cowrie.command.input", "input": "whoami", "session": "s1", "timestamp": "2026-01-01T00:00:02Z"},
    ]
    path = _write(tmp_path, "cowrie.json", lines)

    sessions = parse_log_file(path)

    assert sessions["s1"].command_sequence == ["whoami"]


def test_session_duration_backfilled_when_missing_from_closed_event(tmp_path):
    lines = [
        {"eventid": "cowrie.session.connect", "session": "s1", "src_ip": "1.2.3.4", "protocol": "ssh",
         "timestamp": "2026-01-01T00:00:00.000000Z"},
        {"eventid": "cowrie.session.closed", "session": "s1", "timestamp": "2026-01-01T00:00:12.500000Z"},
    ]
    path = _write(tmp_path, "cowrie.json", lines)

    sessions = parse_log_file(path)

    assert sessions["s1"].session_duration == 12.5


def test_load_logs_merges_same_session_across_multiple_files(tmp_path):
    _write(tmp_path, "cowrie.json.1", [
        {"eventid": "cowrie.session.connect", "session": "s1", "src_ip": "1.2.3.4", "protocol": "ssh",
         "timestamp": "2026-01-01T00:00:00Z"},
        {"eventid": "cowrie.command.input", "input": "whoami", "session": "s1",
         "timestamp": "2026-01-01T00:00:01Z"},
    ])
    _write(tmp_path, "cowrie.json.2", [
        {"eventid": "cowrie.command.input", "input": "ls", "session": "s1", "timestamp": "2026-01-01T00:00:02Z"},
        {"eventid": "cowrie.session.closed", "session": "s1", "duration": 2.0,
         "timestamp": "2026-01-01T00:00:02.500000Z"},
    ])

    sessions = load_logs(tmp_path)

    assert list(sessions.keys()) == ["s1"]
    assert sessions["s1"].command_sequence == ["whoami", "ls"]
    assert sessions["s1"].session_duration == 2.0


def test_to_dataframe_serializes_lists_as_json_and_adds_command_count(tmp_path):
    path = _write(tmp_path, "cowrie.json", [
        {"eventid": "cowrie.session.connect", "session": "s1", "src_ip": "1.2.3.4", "protocol": "ssh",
         "timestamp": "2026-01-01T00:00:00Z"},
        {"eventid": "cowrie.command.input", "input": "wget http://x/y", "session": "s1",
         "timestamp": "2026-01-01T00:00:01Z"},
        {"eventid": "cowrie.session.file_download", "url": "http://x/y", "shasum": "abc123", "session": "s1",
         "timestamp": "2026-01-01T00:00:02Z"},
    ])

    df = to_dataframe(parse_log_file(path))

    row = df.iloc[0]
    assert json.loads(row["command_sequence"]) == ["wget http://x/y"]
    assert json.loads(row["urls_downloaded"]) == ["http://x/y"]
    assert json.loads(row["file_hashes"]) == ["abc123"]
    assert row["command_count"] == 1
