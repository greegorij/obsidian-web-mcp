"""Tests for safe vault_create / vault_append write tools."""

import json
import threading

from obsidian_vault_mcp.tools.read import vault_read
from obsidian_vault_mcp.tools.write import vault_append, vault_create, vault_write


def test_vault_create_creates_new_file(vault_dir):
    result = json.loads(vault_create("safe-create.md", "# New\n\nBody."))
    assert "error" not in result
    assert result["created"] is True
    assert result["path"] == "safe-create.md"
    assert (vault_dir / "safe-create.md").exists()
    read_back = json.loads(vault_read("safe-create.md"))
    assert "Body." in read_back["content"]


def test_vault_create_refuses_existing(vault_dir):
    original = (vault_dir / "test-note.md").read_text(encoding="utf-8")
    result = json.loads(vault_create("test-note.md", "SHOULD_NOT_WRITE"))
    assert result["error"] == "File already exists"
    assert (vault_dir / "test-note.md").read_text(encoding="utf-8") == original
    assert "SHOULD_NOT_WRITE" not in original


def test_vault_create_concurrent_preserves_first_content(vault_dir):
    """O_CREAT|O_EXCL: only one creator wins; loser must not change winner bytes."""
    path = "atomic-create-race.md"
    payloads = ("FIRST_WINS_CONTENT\n", "SECOND_MUST_NOT_APPEAR\n")
    barrier = threading.Barrier(2)
    results: list[dict] = []
    lock = threading.Lock()

    def attempt(content: str) -> None:
        barrier.wait()
        outcome = json.loads(vault_create(path, content))
        with lock:
            results.append(outcome)

    threads = [
        threading.Thread(target=attempt, args=(payload,)) for payload in payloads
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    created = [r for r in results if r.get("created") is True]
    refused = [r for r in results if r.get("error") == "File already exists"]
    assert len(created) == 1
    assert len(refused) == 1

    on_disk = (vault_dir / path).read_text(encoding="utf-8")
    assert on_disk in payloads
    loser = next(p for p in payloads if p != on_disk)
    assert loser not in on_disk


def test_vault_append_appends_existing(vault_dir):
    before = json.loads(vault_read("test-note.md"))["content"]
    result = json.loads(vault_append("test-note.md", "\nAPPENDED_LINE\n"))
    assert "error" not in result
    assert result["appended"] is True
    assert "created" not in result
    after = json.loads(vault_read("test-note.md"))["content"]
    assert after == before + "\nAPPENDED_LINE\n"
    assert after.startswith(before)


def test_vault_append_missing_without_create_flag(vault_dir):
    result = json.loads(vault_append("missing-append.md", "x"))
    assert result["error"] == "File not found"
    assert not (vault_dir / "missing-append.md").exists()


def test_vault_append_create_if_missing(vault_dir):
    result = json.loads(
        vault_append("brand-new-append.md", "first\n", create_if_missing=True)
    )
    assert "error" not in result
    assert result["appended"] is True
    assert "created" not in result
    content = json.loads(vault_read("brand-new-append.md"))["content"]
    assert content == "first\n"

    again = json.loads(vault_append("brand-new-append.md", "second\n"))
    assert again["appended"] is True
    assert "created" not in again
    content2 = json.loads(vault_read("brand-new-append.md"))["content"]
    assert content2 == "first\nsecond\n"


def test_vault_append_never_replaces_body(vault_dir):
    vault_write("append-preserve.md", "KEEP\n")
    json.loads(vault_append("append-preserve.md", "MORE\n"))
    content = json.loads(vault_read("append-preserve.md"))["content"]
    assert content == "KEEP\nMORE\n"
    assert not content.startswith("MORE")


def test_vault_append_does_not_use_read_replace(monkeypatch, vault_dir):
    """Append must use O_APPEND path, not read + write_file_atomic rewrite."""
    from obsidian_vault_mcp import vault as vault_mod
    from obsidian_vault_mcp.tools import write as write_mod

    vault_write("no-read-replace.md", "BASE\n")

    def fail_read(*_a, **_k):
        raise AssertionError("read_file must not be used by vault_append")

    def fail_atomic(*_a, **_k):
        raise AssertionError("write_file_atomic must not be used by vault_append")

    monkeypatch.setattr(vault_mod, "read_file", fail_read)
    monkeypatch.setattr(vault_mod, "write_file_atomic", fail_atomic)
    monkeypatch.setattr(write_mod, "read_file", fail_read)
    monkeypatch.setattr(write_mod, "write_file_atomic", fail_atomic)

    result = json.loads(vault_append("no-read-replace.md", "TAIL\n"))
    assert "error" not in result
    assert (vault_dir / "no-read-replace.md").read_text(
        encoding="utf-8"
    ) == "BASE\nTAIL\n"


def test_vault_append_concurrent_preserves_both(vault_dir):
    """Parallel O_APPEND must keep both chunks (no lost update from read+replace)."""
    path = "concurrent-append.md"
    vault_write(path, "BASE\n")
    payloads = ("AAA\n", "BBB\n")
    barrier = threading.Barrier(2)
    results: list[dict] = []
    lock = threading.Lock()

    def attempt(chunk: str) -> None:
        barrier.wait()
        outcome = json.loads(vault_append(path, chunk))
        with lock:
            results.append(outcome)

    threads = [
        threading.Thread(target=attempt, args=(payload,)) for payload in payloads
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert all("error" not in r for r in results)
    on_disk = (vault_dir / path).read_text(encoding="utf-8")
    assert on_disk.startswith("BASE\n")
    assert "AAA\n" in on_disk
    assert "BBB\n" in on_disk


def test_vault_append_concurrent_respects_max_content_size(monkeypatch, vault_dir):
    """Równoległe appendy: jedna przechodzi limit, druga fail; wygrany chunk zostaje."""
    from obsidian_vault_mcp import config as config_mod

    limit = 100
    monkeypatch.setattr(config_mod, "MAX_CONTENT_SIZE", limit)

    path = "append-size-race.md"
    base = "B" * 60
    vault_write(path, base)
    payloads = ("A" * 30, "C" * 30)
    barrier = threading.Barrier(2)
    results: list[dict] = []
    lock = threading.Lock()

    def attempt(chunk: str) -> None:
        barrier.wait()
        outcome = json.loads(vault_append(path, chunk))
        with lock:
            results.append(outcome)

    threads = [
        threading.Thread(target=attempt, args=(payload,)) for payload in payloads
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    ok = [r for r in results if "error" not in r]
    failed = [r for r in results if r.get("error") == "Invalid path or content"]
    assert len(ok) == 1
    assert len(failed) == 1

    on_disk = (vault_dir / path).read_text(encoding="utf-8")
    on_disk_bytes = on_disk.encode("utf-8")
    assert len(on_disk_bytes) <= limit
    assert on_disk.startswith(base)
    # Wygrany dopisek musi zostać; przegrany nie może być dopisany.
    winners = [p for p in payloads if p in on_disk]
    losers = [p for p in payloads if p not in on_disk]
    assert len(winners) == 1
    assert len(losers) == 1
    assert on_disk == base + winners[0]
    assert ok[0]["size"] == len(on_disk_bytes)


def test_vault_append_create_if_missing_concurrent_keeps_both(vault_dir):
    """Równoległe create_if_missing nie może zgubić chunka (stary read+replace gubił)."""
    path = "append-create-race.md"
    payloads = ("ALPHA\n", "BETA\n")
    barrier = threading.Barrier(2)
    results: list[dict] = []
    lock = threading.Lock()

    def attempt(chunk: str) -> None:
        barrier.wait()
        outcome = json.loads(vault_append(path, chunk, create_if_missing=True))
        with lock:
            results.append(outcome)

    threads = [
        threading.Thread(target=attempt, args=(payload,)) for payload in payloads
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert all("error" not in r for r in results)
    on_disk = (vault_dir / path).read_text(encoding="utf-8")
    assert "ALPHA\n" in on_disk
    assert "BETA\n" in on_disk
    # Samotny jeden chunk = typowa strata z read-miss + write_file_atomic.
    assert on_disk not in payloads
