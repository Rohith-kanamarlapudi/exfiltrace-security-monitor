# USB interface inspection and metadata fingerprints

Windows storage mapping still uses PowerShell/CIM and `Get-CimAssociatedInstance`
for disks → partitions → logical drives. Drive letters are discovered each poll;
all roots feed the existing automatic filesystem watches. The Windows backend now
also enumerates present devnodes using `SetupDiGetClassDevsW` /
`SetupDiEnumDeviceInfo`, reads properties with `CM_Get_DevNode_PropertyW`, and
walks `CM_Get_Parent` relationships. These are read-only Windows APIs. No settings,
keystrokes, device handles, raw descriptors or network traffic are accessed.

`setupapi.py` collects instance ID, parent, container, Windows PnP class, hardware
and compatible IDs, manufacturer, name and capabilities. `inspection.py` groups
each non-MI `USB\VID_xxxx&PID_xxxx` root with its nearest related USB, USBSTOR,
HID and SCSI descendants. Nested USB devices have their own roots. Bluetooth peers
and software-enumerated devices are excluded. Container IDs are displayed, but
never used alone to merge: Windows sometimes uses the same sentinel container for
multiple internal devices. VID/PID, timing and serial similarity never determine
group membership. Missing storage ancestry produces a separate partial fallback
record with its mounts intact, no inferred serial and no fingerprint.

Functions come from Windows PnP classes (storage/HID/keyboard/mouse/camera/audio,
etc.) and the explicit `USB\COMPOSITE` compatible ID. The interface list is a PnP
devnode/function list, not a count of USB descriptor interfaces. HID collection
nodes and the physical root can both appear. Manufacturer/product values can be
driver-provided generic strings. `CM_DEVCAP_UNIQUEID` permits reporting the USB
root's bus-provided unique instance suffix as serial, with that source stated;
without it serial is null. It is not independent raw-descriptor verification.

## Identity and deterministic fingerprint

Physical identity is the uppercase Windows root instance ID, scoped to the
observation source. Serial-less hardware may gain a new identity when moved to
another port. Two devices with the same VID/PID remain separate physical records,
even if their metadata hashes are equal. IDs and hashes can be spoofed: neither
is cryptographic device authentication.

Fingerprint version: `windows-pnp-metadata-v1`. SHA-256 hashes UTF-8 JSON with
sorted object keys, compact separators, `ensure_ascii=False` and explicit nulls.
The canonical object contains version, VID, PID, root manufacturer and product,
plus each interface's Windows PnP class, hardware IDs, compatible IDs and functions.
ID/function arrays are uppercase where appropriate, deduplicated and sorted;
interface objects are sorted by their sorted-key JSON representation. Duplicate
interface objects are retained, so function multiplicity remains meaningful.
Serial, instance/parent/container IDs, interface friendly names, database IDs,
timestamps, mount letters, connection state and polling order are excluded.
The hash is a **metadata fingerprint**, never a descriptor hash. Raw descriptors,
USB version, descriptor class codes, power and firmware revision are null.

Detailed properties are cached until inventory changes or 60 seconds elapse.
Storage/volume associations are refreshed every poll. `inspection.collectedAt`
is the last property collection time; observation `lastSeen` is the latest
successful presence observation. A characteristic change without inventory
change may take up to 60 seconds plus a poll to appear.

## Persistence, failures and API

`history.py` adds `usb_observations` and `usb_fingerprint_history` to the existing
SQLite database without replacing or modifying legacy event/file/alert tables.
One observation row is updated per physical identity; history rows are inserted
only for an initial reliable fingerprint or a changed hash. New timestamps use
ISO 8601 UTC ending in `Z`. Existing timestamps/data remain untouched.

`GET /api/usb/devices` keeps its existing wrapped list and legacy storage fields,
adding camelCase `observationSource`, `inspection`, `fingerprint`, and `observation`.
The observation contains firstSeen, lastSeen, current/previous fingerprint, history
with before/after field differences, fingerprintRetained, and newlyObserved.
`newlyObserved` means first recorded by this database during this monitoring run;
it remains true for that run and becomes false after restart. Startup insertion
events still say preexisting: first observation is not physical insertion time.
Simulated/test identities are source-scoped and labeled separately from Windows.
`GET /api/usb/observations` returns persisted identities, first/last seen and last
reliable characteristics even when disconnected. Existing `/api/usb/events` and
`/api/status` consumers and mounted-drive callbacks remain supported.

Enumeration errors retain the last snapshot and expose `usb_monitor.last_error`.
Native enumeration must end with ERROR_NO_MORE_ITEMS; another termination is a
failure. Property failures are contained, diagnosed and make collection partial;
partial cycles defer removals and hash comparisons. Previously available root
metadata or interface ID arrays becoming unavailable also defer comparison and
retain the previous hash. A query/inventory race causes a retry next poll. Missing
optional values are null or empty arrays, not invented values. Conservative
partial behavior can delay confirmed removals until collection recovers. Legitimate
composites, first observation and changed metadata never generate BadUSB alerts.
BadUSB verdicts and write protection remain unavailable.

## Windows website verification

1. From the project root, start the backend in PowerShell:
   `& .\backend\.venv\Scripts\python.exe .\backend\run.py`
   The existing `backend/config.json` is used unchanged. USB backend must be
   `auto` or `windows`, not `simulated`/`none`. Use the normal account first;
   if Windows denies CIM access, use an account permitted to query local CIM.
2. In a second terminal run `npm.cmd run dev`. Open the URL printed by Vite and
   select **USB Forensics** (`/usb`). The existing `VITE_API_URL` must point to
   the backend `/api` URL; restart Vite after changing environment configuration.
3. Confirm the monitor is running and the page lists physical USB peripherals,
   including built-in USB devices. Select the mouse or keyboard: inspect its
   physical ID, parent/container and HID/function rows. Windows' Device Manager
   → device Properties → Details can independently show Device instance path,
   Parent, Container ID, Hardware IDs and Compatible IDs.
4. Select a composite device. Its MI children should share the physical root's
   parent ancestry and appear in one device's interface list. Two same-model
   devices should remain separate rows; equal fingerprints are possible.
5. Attach a storage device. Wait for a successful poll (normally about three
   seconds plus enumeration). Confirm dynamically discovered mounts and removable
   watches in the health area. No code assumes `D:` or label `LARP`. Select it and
   record its firstSeen, metadata hash, collection time and baseline history entry.
6. Leave it attached over several polls and at least 60 seconds. lastSeen should
   advance, the hash should remain stable, and history should not gain duplicate
   entries. A friendly-name/driver characteristic change can change metadata;
   no BadUSB verdict should appear. Reordered interfaces or a changed drive letter
   alone should not change the hash.
7. Safely eject/unplug and reconnect. On a complete poll, the device disappears
   and its watch is removed; reconnect restores it and its history. Restart the
   backend with the same database: firstSeen/hash history persist, newlyObserved
   becomes false, and currently attached devices get preexisting startup events.
   Serial-less devices moved to another port may become a new identity.
8. To verify sensitive-copy detection, use a harmless disposable file named
   `confidential-usb-check.txt` in an already monitored folder. Copy it to a
   dynamically discovered USB volume and check File Monitoring/alerts for a
   VERIFIED_TRANSFER based on matching content hashes. Do not use real secrets.
9. Stop the backend temporarily: the webpage should keep its last data and show
   an error/stale notice. Restore it and verify refresh recovery. Unsupported
   fields should always read Unavailable, and test/simulated data must not be
   described as physical Windows observations.

## Validation performed (2026-10-12)

- 79 backend tests passed, including representative Windows devnode fixtures,
  composite/same-VID-PID grouping, mouse/keyboard/non-storage/missing serial,
  reordered interfaces and drive-letter stability, characteristic differences,
  partial failures/recovery, caching/query races, restart persistence, API
  compatibility, and sensitive-copy detection with real temporary-folder watches.
- 10 frontend normalization/polling tests passed; lint and production build passed.
  Vite reports the existing large-bundle warning.
- Physical read-only Windows check: Realtek USB Bluetooth radio, USB HID mouse,
  HP camera composite with two MI children, and a separate composite device with
  an NDIS function. All four were complete and had stable hashes across two polls.
  Measured full cycle ~1.07 s and cached cycle ~0.60 s on this host.
- No USB storage volume was attached during that hardware check. Storage mapping,
  unplug/replug, multi-volume behavior and copying were verified using fixtures
  and temporary folders, not the historical physical LARP drive. Browser rendering
  was build-validated; no controllable browser surface was available for visual QA.

API references: [Configuration Manager properties](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_get_devnode_propertyw),
[Container IDs](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/devpkey-device-containerid).
