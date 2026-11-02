"""Cross-platform capture prerequisites: TShark lookup and interface choice.

Only the Python standard library is used so the same code path works on macOS,
Windows and Linux.  Nothing here needs capture privileges: locating ``tshark``
and listing interfaces with ``tshark -D`` are read-only operations.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

#: Environment variable holding an explicit ``tshark`` executable/directory.
TSHARK_ENV_VAR = "EXFILTRACE_TSHARK_PATH"

_MACOS_COMMON_DIRS = (
    Path("/opt/homebrew/bin"),
    Path("/usr/local/bin"),
    Path("/Applications/Wireshark.app/Contents/MacOS"),
)

_WINDOWS_FALLBACKS = (
    Path(r"C:\Program Files\Wireshark"),
    Path(r"C:\Program Files (x86)\Wireshark"),
)

_LOOPBACK_NAMES = frozenset({"lo", "lo0", "lo1", "any"})
_WIFI_HINTS = ("wi-fi", "wifi", "wireless", "wlan")


class CaptureSetupError(RuntimeError):
    """Base error for capture prerequisite or configuration problems."""


class TSharkNotFoundError(CaptureSetupError):
    """TShark could not be located."""


class CaptureInterfaceError(CaptureSetupError):
    """The requested capture interface is missing or ambiguous."""


@dataclass(frozen=True)
class CaptureInterface:
    """One entry from ``tshark -D``.

    ``index`` is the number printed by TShark (``None`` on Windows builds that
    print no numeric prefix).  ``name`` is the device identifier accepted by
    TShark (``en0`` on macOS, ``\\Device\\NPF_{GUID}`` on Windows) and
    ``description`` is the friendly name shown in parentheses (``Wi-Fi``).
    """

    index: Optional[int]
    name: str
    description: Optional[str] = None


def is_windows(platform: Optional[str] = None) -> bool:
    """True on Windows."""
    return (platform or sys.platform).startswith("win")


def is_macos(platform: Optional[str] = None) -> bool:
    """True on macOS."""
    return (platform or sys.platform) == "darwin"


def _binary_name(platform: Optional[str] = None) -> str:
    return "tshark.exe" if is_windows(platform) else "tshark"


def _windows_common_paths() -> list[Path]:
    """Wireshark install locations, honouring ProgramFiles if it is set."""
    paths: list[Path] = []
    for variable in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(variable)
        if root:
            paths.append(Path(root) / "Wireshark")
    paths.extend(_WINDOWS_FALLBACKS)
    return paths


def _common_dirs(platform: Optional[str] = None) -> list[Path]:
    """Platform-specific install directories searched after ``PATH``."""
    if is_windows(platform):
        return _windows_common_paths()
    if is_macos(platform):
        return list(_MACOS_COMMON_DIRS)
    return [Path("/usr/bin"), Path("/usr/local/bin"), Path("/usr/lib/tshark")]


def _tshark_candidates(explicit: Optional[str], platform: Optional[str] = None) -> list[Path]:
    """Return candidates in lookup order: flag, env var, PATH, common dirs."""
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    env_value = os.environ.get(TSHARK_ENV_VAR)
    if env_value:
        candidates.append(Path(env_value).expanduser())
    on_path = shutil.which("tshark")
    if on_path:
        candidates.append(Path(on_path))

    binary = _binary_name(platform)
    for directory in _common_dirs(platform):
        candidates.append(directory / binary)

    # De-duplicate while keeping priority order.
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def _resolve_executable(candidate: Path, platform: Optional[str] = None) -> Optional[Path]:
    """Accept a file path or an install directory; return the resolved file."""
    try:
        if candidate.is_dir():
            candidate = candidate / _binary_name(platform)
        if candidate.is_file():
            return candidate.resolve()
    except OSError:  # pragma: no cover - defensive on odd filesystems
        return None
    return None


def _missing_tshark_message(platform: Optional[str] = None) -> str:
    lines = [
        "TShark was not found. Install Wireshark/TShark, then retry.",
        "  macOS: install Wireshark (brew install --cask wireshark, or wireshark.org).",
        "         The installer includes the ChmodBPF helper for non-sudo capture.",
        "  Windows: install Wireshark with the Npcap option; make sure tshark.exe is on PATH",
        "           or set EXFILTRACE_TSHARK_PATH / pass --tshark-path.",
        "  Linux: install the tshark package and grant capture rights to dumpcap.",
        "This tool never requires sudo.",
    ]
    return "\n".join(lines)


def find_tshark(explicit: Optional[str] = None, *, platform: Optional[str] = None) -> str:
    """Locate TShark in the documented order and return its absolute path.

    Order: ``--tshark-path`` argument, ``EXFILTRACE_TSHARK_PATH`` environment
    variable, ``PATH`` (``shutil.which``), then common install locations.
    """
    for candidate in _tshark_candidates(explicit, platform):
        resolved = _resolve_executable(candidate, platform)
        if resolved is not None:
            return str(resolved)
    raise TSharkNotFoundError(_missing_tshark_message(platform))


def parse_tshark_interfaces(stdout: str) -> list[CaptureInterface]:
    """Parse ``tshark -D`` output on macOS/Linux and Windows.

    macOS/Linux: ``1. en0 (Wi-Fi)``
    Windows:     ``\\Device\\NPF_{GUID} (Wi-Fi)`` (numeric prefix optional)
    """
    entries: list[CaptureInterface] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = re.match(r"^(\d+)\.\s+(.+)$", line)
        index = int(match.group(1)) if match else None
        rest = (match.group(2) if match else line).strip()
        if not rest:
            continue
        name, description = rest, None
        if " " in rest:
            # Device names never contain spaces (en0, eth0, \Device\NPF_{GUID});
            # the remainder is the friendly description and may itself contain
            # parentheses (macOS prints e.g. "en3 (Ethernet Adapter (en3))").
            name, remainder = rest.split(" ", 1)
            remainder = remainder.strip()
            if remainder.startswith("(") and remainder.endswith(")"):
                description = remainder[1:-1].strip() or None
        name = name.strip()
        if name:
            entries.append(CaptureInterface(index=index, name=name, description=description))
    return entries


def discover_interfaces(
    tshark_path: Optional[str] = None, *, platform: Optional[str] = None
) -> list[CaptureInterface]:
    """Run ``tshark -D`` and return the parsed interface list."""
    executable = find_tshark(tshark_path, platform=platform)
    try:
        result = subprocess.run(
            [executable, "-D"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CaptureSetupError(f"Could not run '{executable} -D': {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise CaptureSetupError(f"'{executable} -D' failed ({result.returncode}): {detail}")

    entries = parse_tshark_interfaces(result.stdout or "")
    if not entries:
        raise CaptureInterfaceError(
            "TShark did not report any capture interfaces. Install Wireshark with "
            "Npcap (Windows) or the ChmodBPF helper (macOS), then retry."
        )
    return entries


def _describe(entry: CaptureInterface) -> str:
    index = f"{entry.index}. " if entry.index is not None else ""
    description = f" ({entry.description})" if entry.description else ""
    return f"{index}{entry.name}{description}"


def resolve_interface(
    selector: str,
    entries: Optional[Sequence[CaptureInterface]] = None,
    tshark_path: Optional[str] = None,
    *,
    platform: Optional[str] = None,
) -> str:
    """Resolve a TShark index, device name or friendly name to a device name."""
    if entries is None:
        entries = discover_interfaces(tshark_path, platform=platform)
    entries = list(entries)
    wanted = selector.strip()
    if not wanted:
        raise CaptureInterfaceError("Capture interface must not be empty.")

    if wanted.isdigit():
        index = int(wanted)
        for entry in entries:
            if entry.index == index:
                return entry.name

    for entry in entries:
        if entry.name == wanted:
            return entry.name

    folded = wanted.casefold()
    for entry in entries:
        if entry.name.casefold() == folded:
            return entry.name
        if entry.description and entry.description.casefold() == folded:
            return entry.name

    available = ", ".join(_describe(entry) for entry in entries) or "(none)"
    raise CaptureInterfaceError(
        f"Capture interface {selector!r} is not available. tshark -D reports: {available}"
    )


def _is_loopback(entry: CaptureInterface) -> bool:
    name = entry.name.casefold()
    description = (entry.description or "").casefold()
    if "loopback" in description:
        return True
    if name in _LOOPBACK_NAMES:
        return True
    return bool(re.fullmatch(r"lo\d*", name))


def _interface_rank(entry: CaptureInterface) -> int:
    """Preference order: Wi-Fi, other physical, Ethernet, virtual/pseudo."""
    name = entry.name.casefold()
    text = f"{name} {entry.description or ''}".casefold()
    if any(hint in text for hint in _WIFI_HINTS):
        return 0
    if name.startswith(("en", "wlp")):
        return 1
    if "ethernet" in text or name.startswith("eth"):
        return 2
    if "local area connection*" in text or "virtual" in text or "vpn" in text or "tap" in text:
        return 9
    return 5


def interface_is_up(
    name: str, description: Optional[str] = None, *, platform: Optional[str] = None
) -> bool:
    """Best-effort link-state check using only portable, dependency-free data.

    There is no cross-platform stdlib API for adapter state.  TShark's friendly
    description is therefore the only portable signal: clearly disconnected or
    disabled pseudo-adapters are skipped and everything else is treated as a
    candidate.  This keeps auto-detection working on macOS and Windows without
    invoking ``ifconfig``, ``ip`` or any shell command (see README, Windows
    UNTESTED ON WINDOWS).
    """
    text = f"{name} {description or ''}".casefold()
    down_hints = ("disconnected", "unplugged", "not connected", "disabled")
    if any(hint in text for hint in down_hints):
        return False
    return re.search(r"(?<![a-z])down(?![a-z])", text) is None


def detect_default_interface(
    entries: Optional[Sequence[CaptureInterface]] = None,
    tshark_path: Optional[str] = None,
    *,
    platform: Optional[str] = None,
) -> str:
    """Pick the first suitable non-loopback, up interface."""
    if entries is None:
        entries = discover_interfaces(tshark_path, platform=platform)
    suitable = [entry for entry in entries if not _is_loopback(entry)]
    if not suitable:
        raise CaptureInterfaceError(
            "TShark only reported loopback interfaces; connect a network adapter "
            "or pass --interface explicitly."
        )

    up = [
        entry
        for entry in suitable
        if interface_is_up(entry.name, entry.description, platform=platform)
    ]
    pool = up or suitable
    # ``min`` is stable, so equal-ranked entries keep the tshark -D order.
    return min(pool, key=_interface_rank).name


def explain_capture_error(exc: BaseException, *, platform: Optional[str] = None) -> str:
    """Map low-level TShark/PyShark failures to actionable platform messages."""
    platform = platform or sys.platform
    text = str(exc).casefold()

    if is_windows(platform):
        if any(
            key in text
            for key in (
                "npf",
                "npcap",
                "winpcap",
                "driver isn't running",
                "driver is not running",
                "no interfaces found",
            )
        ):
            return (
                "Windows packet capture driver (Npcap) is missing or not running. "
                "Install Wireshark with Npcap, keep the Npcap driver enabled, and "
                "enable non-admin capture during setup if you do not want to run the "
                "terminal as Administrator. No sudo is needed."
            )
        if any(
            key in text
            for key in (
                "access is denied",
                "permission denied",
                "administrator",
                "elevated",
                "error opening adapter",
                "failed to set hardware filter",
            )
        ):
            return (
                "Windows denied packet capture. Npcap may be installed with "
                "'Restrict Npcap driver's access to Administrators only' enabled. "
                "Reinstall Npcap with that option unchecked to allow non-admin "
                "capture, or run the terminal as Administrator. No sudo is needed."
            )
        return (
            f"Live capture failed on Windows: {exc}. Verify with 'tshark -D', install "
            "Wireshark with Npcap, and run the terminal as Administrator if needed."
        )

    if is_macos(platform):
        if any(
            key in text
            for key in (
                "permission denied",
                "bpf",
                "biocsetif",
                "don't have permission",
                "operation not permitted",
            )
        ):
            return (
                "macOS denied access to the BPF capture devices. Install Wireshark's "
                "ChmodBPF helper (it ships with Wireshark), then log out and back in "
                "so the group membership takes effect. Verify with 'ls -l /dev/bpf*' "
                "and 'tshark -D'. Do not use sudo."
            )
        return f"Live capture failed on macOS: {exc}. Verify with 'tshark -D'."

    return f"Live capture failed: {exc}. Verify TShark with 'tshark -D'."
