# Android Bridge changelog

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
