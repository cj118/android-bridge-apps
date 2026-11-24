# Android Bridge changelog

## 0.3.31

- **Control pages opened from a Home Assistant notification now work.** Cause:
  the UI session's origin binding was taken only from the `Origin` header of
  the sign-in POST. A notification opens the panel through the Home Assistant
  app, where that POST arrives from an opaque context (`Origin: null`, no
  `Sec-Fetch-Site`), so the session was stored with `origin = None`. The same
  page then sent a real `Origin` on `POST /control/approve`, `_origin_error()`
  had nothing to compare it with, and it refused with
  `control_forbidden reason=origin_unbound`. The sidebar path signs in from a
  normal https document, so its `Origin` was bound and it kept working.
  - Sign-in now binds the origin from the `Origin` header, or, when that is
    opaque or absent, from a `Referer` whose **path starts with the validated
    ingress prefix** (`/api/hassio_ingress/<token>`). That prefix only exists
    in a URL actually served through the ingress, so a foreign page cannot
    supply it, and `Sec-Fetch-Site: cross-site` still refuses the sign-in.
  - A session that is still unbound (created by an older build, or where the
    browser sent no usable header at sign-in) binds **once** on its first
    approval POST under the same conditions: ingress peer, `Sec-Fetch-Site`
    missing or `same-origin`, and an ingress-prefixed `Referer` naming the
    presented origin. It is logged as `origin_bound source=referer`.
  - The CSRF token, the single-use login nonce, the ingress peer anchor and
    the allowed-HA-user check are unchanged; the token is still required on
    every approval, and no request may bind an origin it cannot corroborate.
- **STOP always works.** A signed-in, still-allowed Home Assistant user coming
  through the ingress peer can press STOP from an out-of-date page or with a
  mismatched origin: the HA user header set by the ingress proxy is trusted,
  or, when only the session cookie survives, the session's recorded user. STOP
  only removes access, so CSRF and origin are deliberately not consulted on
  that one path. Everything that grants or uses access keeps its full checks,
  and a test asserts that a mismatched-origin approval is still refused.
- **Friendly out-of-date page.** A browser that is refused a control action
  now gets an HTML page (still HTTP 403) saying "This page is out of date.
  Please reload it and try again.", with a link back to the control page and a
  working STOP button. API, MCP and other non-browser clients still receive
  the JSON `{"error":"forbidden"}`.
- **Floating windows are named instead of the element underneath.** The UI
  dump only contains the app's own view hierarchy, so a picture-in-picture or
  overlay window was invisible: the card said "Settings" while the tap would
  have hit the video. `dumpsys window windows` (read-only) is now parsed for
  window package, type, frame and visibility. When a floating or overlay
  window covers the tap point the approval card names it (for example
  "YouTube floating window"), shows the red warning "A floating window covers
  this point - the tap will hit it", and the `android_tap` result reports
  `floating_window`, `floating_window_warning`, `underlying_target` and
  `floating_checked`. Split-screen panes and the app already in front are not
  reported, and an unreadable dump is reported as `floating_checked: false`
  rather than as a clear point. At approval the check runs again: if a
  floating window appeared, moved or closed, the approval fails with detail
  `floating_window` / `floating_window_gone` and nothing is sent; if the same
  window is still there, the already-warned tap proceeds.
- New tests cover all four: notification sign-in binding (and refusal of a
  cross-site or foreign Referer, and of a non-ingress peer), STOP from a
  mismatched origin, without CSRF, from a foreign peer and from a disallowed
  user, the friendly page's text, link and STOP form, and floating-window
  parsing, card naming, proposal reporting, and approval-time refusal. The
  Dockerfile test still passes.
- Version metadata, the application `VERSION` constant, MCP
  `serverInfo.version` and `config.yaml` all report 0.3.31.

## 0.3.30

- `android_action_result` takes an optional `wait_seconds` (0-240, default 0).
  It blocks until the action leaves `pending`/`approved`, returning as soon as
  the action is executed, rejected, expired, cancelled by STOP, or the wait
  runs out. A STOP wakes a waiting call immediately instead of leaving it to
  finish its wait. `wait_for()` in `control.py` waits on a condition notified by
  every approval state change; the records themselves, CSRF, the login nonce
  and single-use approvals are unchanged.
- The `android_tap`, `android_swipe`, `android_text` and
  `android_action_result` tool descriptions now tell the caller to poll with
  `wait_seconds` 180, repeat while pending, and never end the turn while an
  action is pending.
- The Control page approval card now shows a large green **Approve** button and
  a large red **Reject** button, at least 64 px tall with 1.5 rem of clear space
  between them, so a phone tap is unambiguous.
- On press, the pressed button changes colour and its label becomes
  `Approving...` or `Rejecting...`, and both buttons in the card are disabled so
  a second press cannot submit twice. This is one fixed inline script; the page
  sets no Content-Security-Policy and none was added or weakened. The script is
  static markup only: no user or flash value is ever placed in it, and the
  escaping tests still assert that an injected value creates no extra script.
- A large banner now appears at the top of the Control page after a decision:
  green `✓ Approved - tap sent` (or `swipe sent` / `typing sent`) or red
  `✗ Rejected`. It also appears for an approval that had already expired or had
  already been used, red and stating that nothing was sent.
- New tests cover: waiting then returning `executed`, returning on reject,
  returning on STOP, timeout leaving `pending`, and out-of-range
  `wait_seconds` being refused; the button markup, the banner messages, and the
  double-press lock.
- Version metadata, the application `VERSION` constant, MCP `serverInfo.version`
  and `config.yaml` all report 0.3.30.

## 0.3.29

- Fix a fatal startup crash in 0.3.28. `app/server.py` imports `annotate`, but
  the Dockerfile copied app modules one file at a time and `app/annotate.py`
  was never listed, so the container died at import time with
  `ModuleNotFoundError: No module named 'annotate'` and `/app/server.py`
  line 27.
- The Dockerfile now copies every app module in a single instruction,
  `COPY app/*.py /app/`. Ownership and permissions are unchanged: files stay
  root-owned with the source modes the per-file copies produced.
- New `tests/test_dockerfile.py` parses the Dockerfile's `COPY`/`ADD`
  instructions, resolves them against the build context and fails if any
  `app/*.py` module would not end up in the image, so a module added later
  cannot be silently dropped again. It also fails if an app copy gains
  `--chown` or `--chmod`, and it self-checks that it really detects a dropped
  module.
- Version metadata, the application `VERSION` constant, `/status`,
  MCP `serverInfo.version` and `config.yaml` all report 0.3.29.
- No functional change to viewing, pairing, approvals, STOP, the tool
  allowlist or the MCP gates.

## 0.3.28

- `android_screenshot` accepts two read-only options. `grid` draws lines every
  100 device px, bolder and larger-labelled every 200 px, labelled in device
  coordinates with a high-contrast band and label background. `region`
  returns a full-resolution crop of a validated device-pixel area with the
  same device-coordinate grid. Every screenshot result now also includes the
  device width and height and a note that the image may be downscaled and only
  device coordinates may be used for taps.
- The tap approval card now shows `Target NOT verified - check the marker
  carefully` plus a full-resolution zoom around the tap point with a
  crosshair-and-ring marker when no clickable element is found. The existing
  full screenshot and overlay are unchanged.
- Grid, region and the zoom are read-only. Approvals, STOP, identity checks,
  swipe edge rules, the tool allowlist and the MCP gates are unchanged.
- New test asserts `config.yaml` version equals `server.VERSION`.

## 0.3.27

- Version-label correction. The application `VERSION` constant still said
  0.3.25 after the 0.3.26 build, so the startup banner, `/status` version and
  MCP `serverInfo.version` disagreed with the add-on metadata. All of them now
  report 0.3.27, matching `config.yaml`.
- No functional change. Connect without pairing, the saved ADB port and
  hardware identity checks, the seven tools, human approval for tap/swipe/
  text, reject and STOP, approval notifications, and the existing saved
  pairing and credentials are unchanged.

## 0.3.26

- New `Connect (no pairing)` form under `Connect saved tablet`. The host is the
  saved host and is not editable; only the connect port is entered, pre-filled
  with the saved port. It posts to the existing `/connect` behind the HA-user
  session and CSRF token, and a bearer token is still refused.
- The handler validates the port (1-65535), connects `saved_host:port`, requires
  exactly one transport for that host on that port, then reads `ro.serialno` and
  the model and requires them to match the saved identity before writing. On
  success the new port is saved atomically and the saved serial and model are
  left unchanged. On any failure the transport is disconnected and nothing is
  written.
- Log lines are fixed: `connect_port updated` on success, and
  `connect_failed reason=<category>` on failure. Flash messages name the reason
  (`invalid_port`, `connection_refused`, `identity_mismatch`, ...).
- Identity hardening: resolving a transport for the saved host now verifies
  `ro.serialno` when the transport port differs from the saved port, and before
  every screenshot, tap, swipe or text proposal. A mismatch is refused as
  `identity_mismatch`. The verified serial is cached per transport for 60 s.
- The control page shows the saved address (`host:port`) and the last reconnect
  result.
- No change to approvals, tap, swipe, text, STOP, notifications, pairing, the
  tool allowlist or any other security behaviour.
- Wireless ADB port discovery via mDNS is not added: the image's adb has no
  mDNS service, and the network mode is unchanged.

## 0.3.25

- Friendly app names for the approval-card headline: `com.android.settings.intelligence`
  now reads "Settings search", `io.homeassistant.companion.android` reads
  "Home Assistant", `com.sec.android.app.launcher` reads "Home screen" and
  `com.samsung.android.app.routines` reads "Modes and Routines".
  `com.android.settings` stays "Settings" and `com.android.chrome` stays
  "Chrome". Unknown packages keep the existing readable fallback: the last
  package segment with each word capitalised.
- Presentation only. Approval, security, tap, swipe, text and notification
  behaviour is unchanged.

## 0.3.24

- New read-only `GET /pending_summary`, reachable only from Home Assistant
  Core. The socket peer address is compared with Core's address on the hassio
  network (`homeassistant`, resolved at runtime and cached for 30 s, with
  `172.30.32.1` as the documented fallback). `X-Forwarded-For` and every other
  forwarding header are ignored. Any other peer - the OpenCode add-on, the
  Supervisor ingress proxy, a LAN address - gets `403 {"error":
  "forbidden"}`. No session, CSRF token or bearer token is accepted or
  required.
- The response is JSON only: `{"pending": <count>, "headline": "<headline of
  the oldest pending approval or empty>", "oldest_id": "<id or empty>"}`. The
  headline is the one the approval card already shows: `This will tap: button
  "..."` (bounds stripped), `DeepSeek wants to <direction> in <app>.` or
  `DeepSeek wants to type in <app>.`. Typed text, coordinates, screenshots,
  serials, tokens and any id other than `oldest_id` are never included.
- The endpoint only reads the in-memory approval list. It cannot approve,
  reject, expire or alter anything, never captures a screenshot and never runs
  ADB. Approving or rejecting still happens only on the Home Assistant user
  control page.
- Existing approval, tap, swipe, text, STOP and security behaviour is
  unchanged.

## 0.3.23

- `android_text` is now a real approval-gated action instead of a schema stub.
  It takes `text`, `purpose` and `reason`, and it is **still not exposed by
  default**: `expose_tools` must name it, exactly like `android_tap` and
  `android_swipe`. The shipped `config.yaml` default lists only the read-only
  tools.
- Text is restricted before any approval exists: 1-200 characters from
  letters, digits, spaces and `.,!@_+:-`, trimmed at both ends. Anything
  else - shell metacharacters, quotes, newlines, non-ASCII - is refused with
  `text contains unsupported characters`. The card, the stored action and the
  input command always carry the same trimmed string.
- A proposal records a fresh screenshot, the foreground package (friendly name
  as for swipes) and the **one** visible, focused, editable field from
  `uiautomator dump`. It is refused when nothing editable is focused
  (`no_focused_text_field`), when several fields are focused at once
  (`ambiguous_text_field`), when the dump fails (`target_unverified`), when the
  foreground app cannot be read or reports no package at all
  (`foreground_unavailable`, and no pending record is created) and for every
  password, PIN, one-time-code, payment-card, account or API-secret field
  (`sensitive_field_refused`). Secret detection reads only metadata - the
  `password` attribute, the class, and whole words in `resource-id`,
  `content-desc` and `hint` - never the field's contents.
- A field's name on the card is its `content-desc`, then its `resource-id`.
  The field's own `text` is never used, so a previous query or an address
  already in the box is not shown to a model.
- The approval card reads: "DeepSeek wants to type in <app>", the destination
  field, the complete text in a space-preserving block with its character
  count, the purpose, the AI reason, the screenshot with the field outlined in
  green, then Approve and Reject. Every value is HTML-escaped.
- Approving repeats the tap and swipe checks and adds two of its own: the same
  hardware serial, the same app package still in front, the same single field
  still focused with identical bounds and name, a fresh screenshot of the same
  size and orientation with the **field's whole rectangle** unchanged, Control
  ON, STOP not pressed, 600 s expiry and single use. Refusals are reported as
  `app_changed`, `target_changed`, `sensitive_field`, `target_unverified` or
  `screen_changed`. An empty or unreadable package on either side of the app
  comparison is `app_changed`, never a skipped check. Nothing is retried and no
  alternative field is ever used.
- Execution runs the fixed argv `adb -s SERIAL shell input text TEXT`, with
  the text re-validated just before use, spaces encoded as `%s` and the text
  passed as one argument. `adb shell` still hands the command to the device
  shell, which is exactly why the character set is restricted: `#` (comment),
  `?` and `*` (globs), quotes, `;`, `|`, `&`, `$`, backticks, parentheses,
  backslashes and newlines are refused. There is no clipboard path. A
  post-action screenshot is captured and returned through the usual
  `android_action_result` payload, which also reports the app, field, purpose
  and character count - never the typed text.
- Text stays out of logs: descriptions report only a character count, stderr
  never contains the phrase, and the error strings are fixed tokens.
- New tests cover validation, wrong-field refusal, sensitive-field refusal,
  approval, rejection, STOP, expiry, replay, app change, screen change and
  typing failure, plus pure-function tests for field selection. Tap and swipe
  behaviour is unchanged.

## 0.3.22

- `android_swipe` is now a full approval-gated gesture instead of a bare
  coordinate pair. It takes `reason` and `purpose` alongside the two points and
  `duration_ms`, and it is **not exposed by default**: `expose_tools` must name
  it, exactly like `android_tap` and `android_text`.
- Every swipe is validated against the screen it was captured from before any
  approval exists: both points inside the screen and at least 80 px from every
  edge (`edge_zone`); a distance of at least 100 px and at most 70% of the
  relevant screen dimension (`distance`); a duration of 300-1500 ms
  (`duration`); and no more than 20 degrees off the vertical or horizontal axis
  (`diagonal`). The direction is derived, never supplied: "scroll down (swipe
  upwards)", "scroll up (swipe downwards)", "swipe left", "swipe right".
- A swipe proposal records a fresh screenshot, the foreground app's friendly
  name from its package (for example `com.android.settings` -> "Settings", with
  a readable fallback for unknown packages) and the clickable element under the
  start point. The proposal result and `android_action_result` report the
  direction, app name, purpose and start target.
- The approval card reads, top to bottom: "DeepSeek wants to <direction> in
  <app>." then Start, End, the purpose, the screenshot with a green circle at
  the start, a red circle at the end and an arrow between them, the AI reason,
  then Approve and Reject.
- Swipe approval repeats the tap checks: a fresh screenshot of the same size
  and orientation, an unchanged area around the start point, the same hardware
  serial, Control ON, single use, 600 s expiry, and STOP cancels. Only then is
  `input swipe x1 y1 x2 y2 duration` run, followed by a post-action screenshot
  and the usual `android_action_result` report.
- Tap, text and every other security behaviour are unchanged.

## 0.3.21

- A tap proposal now runs `uiautomator dump` (fixed command, app user, 12 s
  timeout) and records the smallest visible **clickable** element at the
  proposed point: text, content-desc or resource-id cleaned to 80 printable
  characters plus its bounds. A clickable parent wins over a smaller
  non-clickable text label, so the card names the control that would actually
  be pressed. Invisible elements are ignored.
- An area with no clickable element is never described as empty. It reports
  "No clickable element detected — verify visually." and the card adds
  "Warning: no clickable element detected — this area may still contain
  interactive controls." If the dump fails the description is
  "Unknown — could not check." with the same warning. UIAutomator is not
  treated as proof that an unidentified area is safe.
- The `android_tap` result and `android_action_result` include `tap_target`
  and `tap_target_clickable`, so the model learns what it was about to press
  instead of guessing from coordinates.
- New read-only MCP tool `android_ui_elements` lists visible clickable
  elements (name and bounds, at most 200, `truncated` flag). It requires
  Viewing like every other `tools/call`, and is exposed by default alongside
  `android_screenshot` and `android_status`; `expose_tools` still narrows the
  list.
- Approval rechecks the target immediately before input, after the existing
  fresh-screenshot comparison: it runs UI inspection again and compares the
  detected target and bounds with the proposal. A missing or changed target,
  a new clickable element covering the point, or a failed/ambiguous
  inspection refuses execution (`target_changed` / `target_unverified`) and
  nothing is retried or tapped elsewhere.
- Password and text-field contents are never exposed. Nodes with
  `password="true"` or EditText/password classes contribute only their
  resource-id to descriptions, the approval card and `android_ui_elements`.
- The fixed UI dump file is removed after every inspection, including failed
  ones, so screen text does not linger on the tablet.
- Approval cards, top to bottom: "This will tap: <element>" in large text,
  a red warning line (press a button, or unidentified area), the screenshot
  at full card width with the 72 px red circle and crosshair, the AI reason,
  then Approve and Reject below the picture. Labels are HTML-escaped.
- Security behaviour otherwise unchanged: HA-user sign-in, CSRF and Origin
  checks, the MCP source allowlist, Viewing, hardware serial verification,
  the fresh-screenshot comparison, single-use approvals, Control expiry, the
  safety epoch, STOP and `expose_tools`.

## 0.3.20

- New add-on option `control_minutes` (integer, default 60, allowed 5–240)
  sets the Control session length. Out-of-range or malformed values fail back
  to 60 minutes. Expiry still turns Control off, clears pending approvals and
  increments the safety epoch; STOP is unchanged.
- Tap approval lifetime is now 600 seconds (10 minutes), up from 120. The
  fresh-screenshot and target-area comparison at approval is unchanged, so a
  stale screen is still refused.
- The Control page auto-refreshes every 5 seconds while Control is ON or at
  least one approval is pending, so new TAP cards appear without a manual
  pull-down. Refresh stops when Control is off and nothing is pending. It
  never approves, rejects or executes anything by itself.
- Pending approval cards show the remaining time in minutes and seconds
  (for example `9m 58s`) instead of a bare second count.
- Security behaviour is unchanged: Home Assistant user sign-in, CSRF and
  Origin checks, Viewing, hardware serial verification, the screen-change
  check, single-use approvals, STOP and `expose_tools` all behave as before.

## 0.3.19

- `android_tap` now requires a non-empty human-readable `reason` of at most
  200 characters. The reason, device string and every other displayed value
  are HTML-escaped on the approval card.
- Approval cards show TAP, X/Y, the AI reason, actual screenshot width/height
  and orientation, time remaining, the pre-action screenshot and Approve /
  Reject buttons. A CSS crosshair is positioned from x/width and y/height, so
  it stays aligned when the image is resized; the image is never cropped or
  distorted.
- Tap coordinates are strict integers in `0..width-1` and `0..height-1`, using
  the decoded screenshot dimensions rather than the old 0–4095 range.
- Approval captures a fresh screenshot and compares the decoded pixels in a
  48 px radius around the tap against the proposal image. Rotation, dimension
  changes, invalid captures or material target-area changes fail closed with
  “Screen changed — ask again.” Tolerances are documented in `pngcheck.py`
  (per-channel delta > 24; more than 0.5% of region pixels changed).
- Each proposal stores the verified hardware serial, ADB transport, screen
  dimensions/orientation, coordinates, reason, fingerprint, expiry and a
  safety epoch. Approval rechecks the connected device, transport and hardware
  serial, and never substitutes another tablet.
- Control sessions expire after 15 minutes; expiry blocks proposals and
  approvals and clears pending proposals. Viewing remains independent. The
  panel shows Control ON with remaining time.
- STOP cancels pending work and increments a safety epoch. Approval rechecks
  Control/STOP immediately before ADB input. The panel documents that STOP
  cannot undo a tap already sent.
- Proposal screenshots use the existing capture rate limiter, with a five
  second proposal cooldown and the existing three-pending cap. The first live
  test mode allows only one pending proposal; the class retains the three
  pending capability.
- The Control panel now shows bounded completed results, including executed,
  rejected, expired and failed states, and the post-action screenshot when
  available. Execution success is reported separately from screenshot success.
- Default exposure remains exactly `android_screenshot` and `android_status`.
  Swipe and text implementations are unchanged. Viewing, Control, CSRF,
  Origin, HA-user, replay and bearer restrictions are unchanged.

## 0.3.18

- Run every adb subprocess with an explicit `HOME=/data` and
  `ANDROID_USER_HOME=/data/.android`, independent of the parent environment.
  The app user's passwd home is `/data` and the entrypoint exports both
  variables, so adb no longer tries to create `/home/app/.android` and abort
  before reading the existing key store.
- Start the ADB server with stdin/stdout/stderr on DEVNULL and wait for the
  client, so a detached daemon cannot hold a pipe open and leave defunct adb
  children.
- Log `adb home=/data` at startup (path only).
- Regression tests assert the explicit environment even when the parent
  `HOME` is `/home/app`, verify the start-server DEVNULL/wait contract, and
  check that no unreaped child remains after start-server.
- No security, identity or key-handling behaviour changed.

## 0.3.17

- Initialise the ADB server explicitly before server-dependent operations.
  `adb start-server` runs as the existing unprivileged application user with
  the existing HOME, key store and environment, under a short bounded timeout
  and a single-flight lock. Daemon failures are reported as
  `adb_server_unavailable`, never as a tablet `connection_refused`.
- Save the physical tablet identity from `adb -s <transport> shell getprop
  ro.serialno` instead of `adb get-serialno`, which returns the wireless
  transport address. Empty, unavailable, malformed and address-like serials are
  refused and never saved. The transport address is kept separate.
- Treat a saved transport address, or a missing serial, as a legacy unverified
  record. Only a human-initiated panel connection may enrol a hardware serial.
  A previously verified hardware identity is never overwritten, and a mismatch
  leaves `device.json` byte-for-byte unchanged.
- Compare models with surrounding whitespace trimmed, case-insensitively, and
  with hyphens and underscores equivalent, so `SM-X210` and `SM_X210` match.
  Genuinely different models still fail.
- Startup, lazy, panel, pairing, status and screenshot paths all use the same
  ADB server and identity rules. Failure never prevents the bridge starting.
- Regression tests cover daemon start/failure classification, single-flight
  startup, the application environment, physical-serial validation, legacy
  enrolment, verified-identity preservation, model normalisation, Viewing
  gates and the read-only default tool set.

## 0.3.16

- Fix the Device panel's reconnect form markup. The saved-form fragment was
  placed one argument early in the control page template, so the pair form's
  CSRF field swallowed the whole reconnect form. The browser showed a stray
  `'>` and the raw CSRF token, and `Connect saved tablet` submitted without a
  CSRF token and was refused with 403 `forbidden`.
- Escape every dynamic attribute value in the reconnect and pair forms,
  including the CSRF token and the saved host:port, with
  `html.escape(..., quote=True)`.
- Regression tests render the real control page, parse it with `html.parser`,
  and assert that the CSRF token never appears as visible text, that every
  POST form carries exactly one hidden CSRF field, that the markup is not
  broken, and that the parsed reconnect form submits successfully (303).
- Security behaviour is unchanged: the session, CSRF, origin and
  Viewing/Control gates still apply to `/control/reconnect`.

## 0.3.15

- New `Connect saved tablet` button on the control panel. It reconnects to the
  host and connect port already stored in `device.json`; no pairing code and no
  repeated wireless-ADB pairing are needed.
- The request uses the existing Home Assistant user session, CSRF token and
  origin checks. A bearer token alone, a missing session or a missing CSRF token
  is refused exactly as for the other control actions.
- After connecting, the tablet's serial and `ro.product.model` are read and
  must match any saved identity. The verified identity is then saved, so a
  record created before identities existed gains one.
- An unreadable identity, an ambiguous device listing, or an identity that
  conflicts with the saved serial/model fails safely and leaves `device.json`
  unchanged. A tablet connected during a failed verification is disconnected,
  because the other paths resolve the saved target by host only.
- When no tablet is saved the panel shows `No saved tablet.` instead of the
  button.
- Viewing, control, approval, STOP and the MCP source/Viewing gates are
  unchanged.

## 0.3.14

- Automatic reconnect to the saved tablet. At startup, after the adb key check,
  `/data/private/device.json` is used to run `adb connect` to the saved host and
  connect port only, as the application user. Host and port are validated before
  adb runs; pairing is never started automatically. At most three attempts with
  short backoff and bounded command timeouts; failure never blocks startup.
- A successful `adb connect` is not trusted on its own. The saved identity
  (`serial` from adb `get-serialno`, `ro.product.model`) must match before the
  reconnect counts as successful. Identity is only written by a human-initiated
  pair/connect from the control panel, never by a reconnect.
- A record created before identities existed stores only host and connect port.
  For that record a reconnect accepts one device whose model is `SM_X210` and
  logs `adb reconnect identity unverified`; the real identity is saved the next
  time the tablet is connected from the panel.
- `android_status` and `android_screenshot` (and `/status`, `/screenshot`) make one
  lazy reconnect attempt when the saved device is missing, rate-limited so
  concurrent requests cannot cause repeated attempts.
- Reconnect logging is limited to `adb reconnect ok`,
  `adb reconnect identity unverified` (legacy record only) and
  `adb reconnect failed reason=<category>`. Keys, targets and codes are never
  logged.
- MCP discovery works with Viewing OFF: the allowlisted OpenCode source may call
  `initialize`, `tools/list`, `ping` and notifications. Every `tools/call`,
  including `android_status` and `android_screenshot`, still requires the source
  allowlist AND an open Viewing session.
- New app option `expose_tools` (default `["android_screenshot",
  "android_status"]`). `tools/list` advertises only exposed tools and
  `tools/call` rejects anything else before any Android operation. Unknown names
  are dropped and logged; duplicates are collapsed; missing or invalid settings
  fall back to the read-only default; an empty list exposes nothing. Tap, swipe,
  text and action-result implementations remain in the codebase but are not
  exposed by default and still require the existing approval process.
- Startup log now says `(HA-user panel, MCP source+viewing gate)` instead of the
  misleading `(bearer auth enabled)`. Authentication is unchanged.

## 0.3.13

- Every MCP request now requires both the allowlisted OpenCode source address and
  an open Viewing session. A valid bearer token no longer bypasses either; the
  token is not consulted on `/mcp` at all.
- Viewing sessions carry an expiry (8 hours) and are cleared by STOP and by
  disconnect, so screenshots, action proposals and post-action images stop
  immediately.
- `/screenshot` uses the same viewing predicate as `/mcp`.

## 0.3.12

- Fix: an earlier adb run as root left `/data/.android/adbkey` owned by root, so
  the unprivileged adb server could not read its own key and aborted with
  `error: protocol fault (couldn't read status length)`.
- The entrypoint repairs adb home ownership and modes as root before dropping
  privileges: directory 0700, `adbkey` 0600, `adbkey.pub` 0644, other adb files
  0600, all owned by 10001. Key content is never read or regenerated.
- The server refuses to start as root, so adb cannot run as root again.
- Startup logs `adb key ok`, `adb key missing` or `adb key unreadable`.
- Pair and connect failures log a safe category (`key_unreadable`,
  `connection_refused`, `protocol_fault`, `pairing_rejected`, `unknown`).
  The pairing code is never logged.

## 0.3.11

- The bearer token is no longer sufficient for any device action:
  `/screenshot` also requires an active Viewing session, and `/pair`,
  `/connect`, `/disconnect` and `/window` accept only a signed-in Home
  Assistant user with a valid CSRF token. A bearer-only request gets `403`.
- Pairing moved onto the control page (IP, pairing port, 6-digit code, connect
  port). The code is written to adb on stdin only and is never logged or echoed.
- Target validation: private LAN IPv4 only (10/8, 172.16/12, 192.168/16),
  ports 1-65535, code exactly 6 digits.
- STOP also ends the viewing session, so every screenshot path is refused
  afterwards.
- Startup logs `adb available version=...` or `adb missing`.

## 0.3.10

- Fix: the control page raised `NameError` while rendering a flash message
  (`_safe_text` was called unqualified instead of `self._safe_text`), so every
  `303` redirect ended in `GET /control?flash=... → 500`.
- Flash text is now a fixed whitelist rendered through `html.escape`; unknown
  values render nothing.
- Handler errors log the exception type, file name and line number only.

## 0.3.9

- Fix: `/data/options.json` is Supervisor-managed and readable only by root, so
  the unprivileged server could never load `allowed_ha_users` (the live symptom
  was `login_forbidden reason=ha_user_not_allowed user=carlj`).
- A root-only startup step (`options_bridge.py`) now extracts **only**
  `allowed_ha_users` into `/data/private/allowed_users.json`, written atomically
  with mode 0600 and owned by the application user 10001. No other option,
  token or credential is copied, and `options.json` is never made readable.
- The server reads only that private handoff and fails closed when it is
  missing, malformed, loosely permissioned or owned by another user.

## 0.3.8

- Browser sign-in is bound to the Home Assistant user, not the bearer token.
  Supervisor ingress adds `X-Remote-User-Name` (and strips client-supplied
  copies of the identity headers); a session is created only for a username in
  the new `allowed_ha_users` option. The bearer token is API/MCP only and can
  no longer create a browser session, approve actions or start control.
- `panel_admin: true`.
- Control-page POSTs answer `303` back to the panel; API and MCP clients still
  receive JSON.
- Redirects are built only from a validated `X-Ingress-Path`
  (`/api/hassio_ingress/<token>`). A malformed or missing prefix is rejected
  with `400`, so a redirect can never leave the ingress path. `Host` and
  forwarding headers are never used.
- Sign-in matches `X-Remote-User-Name` exactly against `allowed_ha_users`.
  Display names and GitHub names are not accepted.

## 0.3.7

- Home Assistant ingress supplies neither `Origin` nor `Sec-Fetch-Site` to the
  add-on. A missing or `null` origin is now accepted only from the Supervisor
  ingress peer `172.30.32.2`, and only with a valid session plus the
  session-bound CSRF token. `X-Forwarded-For` is never trusted.
- Sign-in from such a peer requires a single-use, five-minute nonce issued with
  the sign-in page and bound to its cookie. `null` is never stored as an origin.
- Every 403 logs the names of the tracked headers that were present, plus the
  peer address and fetch-site value. Values, cookies, CSRF tokens and ingress
  paths are never logged.

## 0.3.6

- Origin guard: an absent or `null` Origin is accepted only when
  `Sec-Fetch-Site: same-origin`. `same-site`, `cross-site`, `none` and a
  missing value are rejected with `reason=origin_null`.
- Sign-in applies the same rule and never stores `null` as a bound origin.
- Rejection logs include the fetch-site value only. Cookies, CSRF values,
  tokens and ingress paths are never logged.

## 0.3.5

- Session-bound origin check; host equality no longer used (ingress-safe).

## 0.3.4

- Ingress-safe origin validation and rejection reason logging.

## 0.3.3

- Stale `ab_ui` cookie no longer masks a live session.

## 0.3.2

- Root redirect to the control panel; version string corrected.

## 0.3.1

- Root URL redirects to the control panel.

## 0.3.0

- Approval-gated Android input (tap, swipe, text) with UI session, CSRF and STOP.

## 0.2.2

- Read-only screenshots over wireless ADB with a windowed MCP interface.

## 0.2.1

- Startup authentication self-test.

## 0.2.0

- Bearer authentication, status and screenshot placeholder.

## 0.1.0

- Initial read-only stub.
