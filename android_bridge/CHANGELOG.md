# Android Bridge changelog

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
