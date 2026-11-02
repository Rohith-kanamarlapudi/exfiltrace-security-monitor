"""Cross-platform capture setup tests.

Everything here is mocked: no TShark process is started, no capture device is
opened and no platform-specific privileges are needed.  The tests cover both
macOS-style and Windows-style ``tshark -D`` output.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.network import capture, combined, config, platform_support
from backend.network.combined import LiveConfigError, resolve_live_db
from backend.network.platform_support import (
    CaptureInterface,
    CaptureInterfaceError,
    TSharkNotFoundError,
    detect_default_interface,
    explain_capture_error,
    find_tshark,
    parse_tshark_interfaces,
    resolve_interface,
)

MAC_TSHARK_OUTPUT = "1. en0 (Wi-Fi)\n2. en1 (Ethernet)\n3. lo0 (Loopback)\n"
WINDOWS_TSHARK_OUTPUT = (
    "\\Device\\NPF_{11111111-1111-1111-1111-111111111111} (Wi-Fi)\n"
    "\\Device\\NPF_{22222222-2222-2222-2222-222222222222} (Ethernet)\n"
    "\\Device\\NPF_{33333333-3333-3333-3333-333333333333} (Loopback)\n"
)


def _windows_wifi_name() -> str:
    return "\\Device\\NPF_{11111111-1111-1111-1111-111111111111}"


def _windows_ethernet_name() -> str:
    return "\\Device\\NPF_{22222222-2222-2222-2222-222222222222}"


# ---------------------------------------------------------------------------
# TShark lookup
# ---------------------------------------------------------------------------
def test_find_tshark_lookup_order(monkeypatch):
    monkeypatch.setenv(platform_support.TSHARK_ENV_VAR, "/env/tshark")
    monkeypatch.setattr(platform_support.shutil, "which", lambda _name: "/path/tshark")

    seen: list[str] = []

    def fake_resolve(candidate, platform=None):
        seen.append(str(candidate))
        return Path("/chosen/tshark") if str(candidate) == "/path/tshark" else None

    monkeypatch.setattr(platform_support, "_resolve_executable", fake_resolve)

    assert find_tshark("/explicit/tshark") == "/chosen/tshark"
    assert seen[:3] == ["/explicit/tshark", "/env/tshark", "/path/tshark"]


def test_find_tshark_env_var_beats_path(monkeypatch):
    monkeypatch.setenv(platform_support.TSHARK_ENV_VAR, "/env/tshark")
    monkeypatch.setattr(platform_support.shutil, "which", lambda _name: "/path/tshark")

    def fake_resolve(candidate, platform=None):
        return Path("/env/tshark") if str(candidate) == "/env/tshark" else None

    monkeypatch.setattr(platform_support, "_resolve_executable", fake_resolve)
    assert find_tshark() == "/env/tshark"


def test_find_tshark_uses_common_locations_when_path_is_empty(monkeypatch):
    monkeypatch.delenv(platform_support.TSHARK_ENV_VAR, raising=False)
    monkeypatch.setattr(platform_support.shutil, "which", lambda _name: None)

    seen: list[str] = []

    def fake_resolve(candidate, platform=None):
        seen.append(str(candidate))
        if str(candidate).endswith("MacOS/tshark"):
            return Path("/Applications/Wireshark.app/Contents/MacOS/tshark")
        return None

    monkeypatch.setattr(platform_support, "_resolve_executable", fake_resolve)

    found = find_tshark(platform="darwin")
    assert Path(found).as_posix().endswith("MacOS/tshark")
    assert any("/opt/homebrew/bin" in item for item in seen)
    assert any("/usr/local/bin" in item for item in seen)


def test_find_tshark_windows_common_locations(monkeypatch):
    monkeypatch.delenv(platform_support.TSHARK_ENV_VAR, raising=False)
    monkeypatch.setattr(platform_support.shutil, "which", lambda _name: None)
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    monkeypatch.setenv("ProgramFiles(x86)", r"C:\Program Files (x86)")

    candidates = platform_support._tshark_candidates(None, "win32")
    rendered = [candidate.as_posix().replace("\\", "/") for candidate in candidates]
    assert "C:/Program Files/Wireshark/tshark.exe" in rendered
    assert "C:/Program Files (x86)/Wireshark/tshark.exe" in rendered


def test_find_tshark_uses_mocked_sys_platform(monkeypatch):
    monkeypatch.setattr(platform_support.sys, "platform", "win32")
    monkeypatch.delenv(platform_support.TSHARK_ENV_VAR, raising=False)
    monkeypatch.setattr(platform_support.shutil, "which", lambda _name: None)
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    seen: list[str] = []

    def fake_resolve(candidate, platform=None):
        rendered = candidate.as_posix().replace("\\", "/")
        seen.append(rendered)
        if rendered.endswith("Program Files/Wireshark/tshark.exe"):
            return Path(r"C:\Program Files\Wireshark\tshark.exe")
        return None

    monkeypatch.setattr(platform_support, "_resolve_executable", fake_resolve)
    assert find_tshark() == str(Path(r"C:\Program Files\Wireshark\tshark.exe"))
    assert any(item.endswith("Program Files/Wireshark/tshark.exe") for item in seen)


def test_find_tshark_accepts_an_install_directory(tmp_path):
    binary = tmp_path / ("tshark.exe" if platform_support.is_windows() else "tshark")
    binary.write_text("")
    found = platform_support._resolve_executable(tmp_path)
    assert found == binary.resolve()


def test_find_tshark_missing_names_both_platforms(monkeypatch):
    monkeypatch.setattr(platform_support, "_resolve_executable", lambda *_a, **_k: None)
    with pytest.raises(TSharkNotFoundError) as excinfo:
        find_tshark()
    message = str(excinfo.value)
    assert "TShark was not found" in message
    assert "ChmodBPF" in message
    assert "Npcap" in message
    assert "never requires sudo" in message


# ---------------------------------------------------------------------------
# Interface parsing and selection
# ---------------------------------------------------------------------------
def test_parse_macos_tshark_output():
    entries = parse_tshark_interfaces(MAC_TSHARK_OUTPUT)
    assert [entry.name for entry in entries] == ["en0", "en1", "lo0"]
    assert entries[0].index == 1
    assert entries[0].description == "Wi-Fi"


def test_parse_nested_parentheses_in_friendly_name():
    entries = parse_tshark_interfaces("16. en3 (Ethernet Adapter (en3))\n")
    assert entries[0].name == "en3"
    assert entries[0].description == "Ethernet Adapter (en3)"


def test_parse_windows_tshark_output_with_npcap_guids():
    entries = parse_tshark_interfaces(WINDOWS_TSHARK_OUTPUT)
    assert entries[0].index is None
    assert entries[0].name == _windows_wifi_name()
    assert entries[0].description == "Wi-Fi"


def test_parse_windows_tshark_output_with_numeric_prefix():
    entries = parse_tshark_interfaces(
        "1. \\Device\\NPF_{11111111-1111-1111-1111-111111111111} (Wi-Fi)\n"
    )
    assert entries[0].index == 1
    assert entries[0].name == _windows_wifi_name()
    assert entries[0].description == "Wi-Fi"


def test_resolve_interface_by_number_name_and_friendly_name():
    mac_entries = parse_tshark_interfaces(MAC_TSHARK_OUTPUT)
    assert resolve_interface("2", mac_entries) == "en1"
    assert resolve_interface("en0", mac_entries) == "en0"
    assert resolve_interface("Wi-Fi", mac_entries) == "en0"
    assert resolve_interface("wi-fi", mac_entries) == "en0"

    win_entries = parse_tshark_interfaces(WINDOWS_TSHARK_OUTPUT)
    assert resolve_interface("Wi-Fi", win_entries) == _windows_wifi_name()
    assert resolve_interface(_windows_ethernet_name(), win_entries) == _windows_ethernet_name()


def test_resolve_interface_reports_available_interfaces():
    entries = parse_tshark_interfaces(MAC_TSHARK_OUTPUT)
    with pytest.raises(CaptureInterfaceError, match="not available"):
        resolve_interface("en9", entries)


def test_interface_is_up_uses_portable_description_fallback():
    assert platform_support.interface_is_up("en0", "Wi-Fi") is True
    assert platform_support.interface_is_up(r"\Device\NPF_{GUID}", "Ethernet") is True
    assert platform_support.interface_is_up(r"\Device\NPF_{GUID}", "Disconnected") is False
    assert platform_support.interface_is_up("en5", "Adapter disabled") is False


def test_detect_default_interface_prefers_wifi_over_loopback(monkeypatch):
    entries = parse_tshark_interfaces("1. lo0 (Loopback)\n2. en1 (Ethernet)\n3. en0 (Wi-Fi)\n")
    monkeypatch.setattr(platform_support, "interface_is_up", lambda *_a, **_k: True)
    assert detect_default_interface(entries) == "en0"


def test_detect_default_interface_windows_prefers_friendly_wifi(monkeypatch):
    entries = parse_tshark_interfaces(WINDOWS_TSHARK_OUTPUT)
    monkeypatch.setattr(platform_support, "interface_is_up", lambda *_a, **_k: True)
    assert detect_default_interface(entries, platform="win32") == _windows_wifi_name()


def test_detect_default_interface_skips_interfaces_that_are_down(monkeypatch):
    entries = parse_tshark_interfaces(MAC_TSHARK_OUTPUT)
    monkeypatch.setattr(
        platform_support,
        "interface_is_up",
        lambda name, description=None, **_k: name == "en1",
    )
    assert detect_default_interface(entries, platform="darwin") == "en1"


def test_detect_default_interface_falls_back_when_no_state_is_available(monkeypatch):
    entries = parse_tshark_interfaces(WINDOWS_TSHARK_OUTPUT)
    monkeypatch.setattr(platform_support, "interface_is_up", lambda *_a, **_k: False)
    # No interface reports "up"; use the ranked fallback instead of failing.
    assert detect_default_interface(entries, platform="win32") == _windows_wifi_name()


def test_detect_default_interface_rejects_loopback_only(monkeypatch):
    entries = parse_tshark_interfaces("1. lo0 (Loopback)\n")
    with pytest.raises(CaptureInterfaceError, match="loopback"):
        detect_default_interface(entries, platform="darwin")


# ---------------------------------------------------------------------------
# Permission / setup error messages
# ---------------------------------------------------------------------------
def test_macos_permission_error_explains_chmodbpf():
    message = explain_capture_error(
        RuntimeError("You don't have permission to capture on that device (BIOCSETIF failed)"),
        platform="darwin",
    )
    assert "ChmodBPF" in message
    assert "log out and back in" in message
    assert "sudo" in message.lower()


def test_windows_missing_npcap_error():
    message = explain_capture_error(RuntimeError("The NPF driver isn't running"), platform="win32")
    assert "Npcap" in message
    assert "no sudo" in message.lower()


def test_windows_admin_and_non_admin_capture_error():
    message = explain_capture_error(RuntimeError("Access is denied"), platform="win32")
    assert "Administrator" in message
    assert "non-admin" in message.lower()


# ---------------------------------------------------------------------------
# Shutdown handling
# ---------------------------------------------------------------------------
def test_shutdown_handler_is_posix_only(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(combined.signal, "signal", lambda *args: calls.append(args))

    monkeypatch.setattr(combined.sys, "platform", "win32")
    combined._install_shutdown_handler()
    assert calls == []

    monkeypatch.setattr(combined.sys, "platform", "darwin")
    combined._install_shutdown_handler()
    assert calls and calls[0][0] == combined.signal.SIGTERM


# ---------------------------------------------------------------------------
# Paths and demo-database refusal
# ---------------------------------------------------------------------------
def test_default_paths_use_the_platform_temp_directory(monkeypatch):
    monkeypatch.setattr("tempfile.gettempdir", lambda: "/custom/tmp")
    assert config.default_live_db() == Path("/custom/tmp/exfil_live.db")
    assert config.default_demo_db() == Path("/custom/tmp/exfil_demo.db")


def test_resolve_live_db_compares_resolved_absolute_paths(tmp_path, monkeypatch):
    demo = tmp_path / "exfil_demo.db"
    monkeypatch.setattr(config, "default_demo_db", lambda: demo)

    with pytest.raises(LiveConfigError, match="demo database"):
        resolve_live_db(str(tmp_path / "nested" / ".." / "exfil_demo.db"))

    live = tmp_path / "exfil_live.db"
    assert resolve_live_db(str(live)) == str(live.resolve())


def test_resolve_live_db_uses_platform_case_rules(tmp_path, monkeypatch):
    demo = tmp_path / "exfil_demo.db"
    monkeypatch.setattr(config, "default_demo_db", lambda: demo)
    monkeypatch.setattr(combined.os.path, "normcase", lambda value: str(value).lower())

    with pytest.raises(LiveConfigError, match="demo database"):
        resolve_live_db(str(tmp_path / "EXFIL_DEMO.DB"))


# ---------------------------------------------------------------------------
# Event loop selection
# ---------------------------------------------------------------------------
def test_create_capture_event_loop_installs_windows_proactor_policy(monkeypatch):
    created = {}

    class FakePolicy:
        pass

    class FakeLoop:
        pass

    fake_asyncio = SimpleNamespace(
        WindowsProactorEventLoopPolicy=FakePolicy,
        new_event_loop=lambda: created.setdefault("loop", FakeLoop()),
        set_event_loop=lambda loop: created.setdefault("active_loop", loop),
        set_event_loop_policy=lambda policy: created.setdefault("policy", policy),
    )
    monkeypatch.setattr(capture, "asyncio", fake_asyncio)
    monkeypatch.setattr(capture.sys, "platform", "win32")

    loop = capture._create_capture_event_loop()

    assert isinstance(created["policy"], FakePolicy)
    assert created["active_loop"] is loop
    assert isinstance(loop, FakeLoop)


# ---------------------------------------------------------------------------
# PyShark integration
# ---------------------------------------------------------------------------
def test_live_capture_receives_resolved_tshark_path(monkeypatch, temp_db):
    class FakeLiveCapture:
        instances: list["FakeLiveCapture"] = []

        def __init__(self, **kwargs):
            self.kwargs = kwargs
            FakeLiveCapture.instances.append(self)

        def sniff_continuously(self):
            while True:
                yield SimpleNamespace()
                time.sleep(0.01)

        def close(self):
            pass

    monkeypatch.setattr(capture.platform_support, "find_tshark", lambda _explicit=None: "/fake/tshark")
    monkeypatch.setattr(
        capture,
        "discover_capture_interfaces",
        lambda _tshark_path=None: [CaptureInterface(1, "fake0", "Wi-Fi")],
    )
    monkeypatch.setitem(sys.modules, "pyshark", SimpleNamespace(LiveCapture=FakeLiveCapture))

    engine = capture.CaptureEngine(
        db_path=temp_db,
        mode="live",
        interface="fake0",
        tshark_path="/fake/tshark",
        interval_seconds=0.05,
    )
    engine.start()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and not FakeLiveCapture.instances:
        time.sleep(0.01)

    assert FakeLiveCapture.instances
    kwargs = FakeLiveCapture.instances[0].kwargs
    assert kwargs["tshark_path"] == "/fake/tshark"
    assert kwargs["eventloop"] is not None
    assert kwargs["custom_parameters"] == ["-p"]
    engine.stop()
