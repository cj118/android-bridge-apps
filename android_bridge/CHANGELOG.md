# Android Bridge changelog

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
