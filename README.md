# streambot-remote-backend

Cloud backend for Streambot Remote. Rust/Axum + PostgreSQL + Valkey.

## Auth routes

- `GET /auth/bot` — broadcaster/control Twitch authorization. Creates/updates the streamer and opens an owner session.
- `GET /auth/message-bot` — attaches the secondary Twitch chat identity to the currently logged-in owner streamer.
- `GET /auth/mod?streamer=<login>` — moderator login for one streamer.
- callbacks live under the corresponding `/callback` route.

The browser receives only an opaque HttpOnly session cookie. OAuth state and sessions live in Valkey. Twitch access/refresh tokens are AES-256-GCM encrypted before being written to PostgreSQL.

## Streambot instance auth

Owners can create one or more local Streambot instance tokens. The raw token is returned once; only its SHA-256 hash is stored.

Local Streambot can validate its token with:

```http
POST /api/v1/instance-auth
Authorization: Bearer <instance-token>
```

This is intentionally transport-agnostic so WebSocket/mod-control support can be added later without changing identity/auth.

## Run

```bash
cp .env.example .env
# fill Twitch credentials and encryption key
# key example: openssl rand -base64 32
docker compose up --build
```

Register these redirect URLs in the Twitch developer console for local development:

- `http://localhost:8080/auth/bot/callback`
- `http://localhost:8080/auth/message-bot/callback`
- `http://localhost:8080/auth/mod/callback`

## API implemented in v0.1

- session: `/api/v1/me`
- accessible streamers: `/api/v1/streamers`
- mods: `/api/v1/streamers/:id/mods`
- Streambot instances: `/api/v1/streamers/:id/instances`
- local instance authentication: `/api/v1/instance-auth`

## Streambot Twitch OAuth broker

`/auth/bot` and `/auth/message-bot` are credential bootstrap flows for a local Streambot. They are not cloud user logins and do not register a streamer or store Twitch credentials in PostgreSQL.

1. Streambot opens `/auth/bot?return_to=http://localhost:...` or `/auth/message-bot?return_to=...`.
2. Twitch redirects back to the cloud callback.
3. The cloud stores the resulting Twitch token payload in Valkey for 120 seconds under a one-time exchange code.
4. The browser is redirected to the supplied local URL with `code=<one-time-code>`.
5. Streambot calls `POST /api/v1/twitch/exchange` with `{ "code": "..." }`.
6. The response contains `client_id`, `access_token`, `refresh_token`, `expires_in`, `obtainment_timestamp`, scopes and Twitch user information. The exchange code is deleted immediately.

`POST /api/v1/instance-auth` is unrelated to Twitch OAuth and only authenticates already-registered Streambot instances using their bearer instance token.

## Cloud user login

Streamer and moderator access use one Twitch login endpoint:

```text
GET /auth/login
GET /auth/login/callback
```

The Twitch user is created/updated as the owner of their own streamer identity. Moderator access is evaluated dynamically from Streambot-provided Valkey moderator maps, not persisted in the cloud session or PostgreSQL. This flow is separate from `/auth/bot` and `/auth/message-bot`, which are OAuth brokers for local Streambot credentials only.

For localhost development add this OAuth redirect URL in the Twitch Developer Console:

```text
http://localhost:8080/auth/login/callback
```


## Streambot cloud transport

### Pair/register a Streambot from the Streambot itself

The cloud user should already be logged into the panel and connected to `GET /ws/user`.

1. Streambot starts registration:

```http
POST /api/v1/streambot/registration/start
Content-Type: application/json

{"name":"Main Streambot","twitch_login":"eliteschw31n"}
```

The response contains only `pairing_id`, `twitch_login`, and `expires_in`. The PIN is **not** returned to Streambot.

2. The cloud sends the matching logged-in user's panel this WebSocket event:

```json
{"type":"streambot_registration","status":"pending","pairing_id":"...","name":"Main Streambot","twitch_login":"eliteschw31n","pin":"123456","expires_in":30}
```

The panel shows the six-digit PIN. The user types it into the local Streambot admin panel.

3. Streambot verifies it:

```http
POST /api/v1/streambot/registration/verify
Content-Type: application/json

{"pairing_id":"...","pin":"123456"}
```

On success the response contains the permanent instance `token`, `instance_id`, and `streamer_id`. Store the token locally and use it for `/ws/streambot` and `/api/v1/instance-auth`. The PIN expires after 30 seconds and permits at most five attempts.

The panel receives a second `streambot_registration` event with `status: "completed"`. Pending registrations are replayed when `/ws/user` reconnects.

Cloud users can still create an instance directly with `POST /api/v1/streamers/:id/instances`.

### Streambot WebSocket

Connect to:

`GET /ws/streambot?token=<instance-token>`

A Bearer token header is also accepted. The cloud validates the token against the hashed token in PostgreSQL and records the connection as online.

Streambot -> cloud messages are JSON. Supported core messages:

```json
{"type":"moderators","moderators":[{"twitch_user_id":"123","login":"some_mod","display_name":"Some Mod"}]}
```

or a moderator object keyed by Twitch user ID:

```json
{"type":"moderators","moderators":{"123":{"login":"some_mod","display_name":"Some Mod"}}}
```

Moderator maps are saved **only in Valkey** under the instance and are never written to PostgreSQL.

Publish the trimmed remote-panel state with:

```json
{"type":"snapshot","data":{"macros":[],"interactions":[],"status":{}}}
```

`type: "state"` is accepted as an alias for `snapshot`.

The cloud sends actions back through the same socket as:

```json
{
  "type":"action",
  "request_id":"...",
  "action":"macro.run",
  "payload":{"id":"..."},
  "requested_by":{"twitch_user_id":"...","login":"..."}
}
```

### Mod-panel API

All routes use the cloud `/auth/login` session cookie.

- `GET /api/v1/mod/instances` — instances the logged-in user owns or currently moderates.
- `GET /api/v1/mod/instances/:id/state` — trimmed state most recently pushed by Streambot.
- `POST /api/v1/mod/instances/:id/actions` — send an allowed/action name + payload to the connected Streambot.

Example action body:

```json
{"action":"macro.run","payload":{"id":"scene-switch"}}
```

Moderator access is evaluated dynamically from the latest Valkey moderator map. A moderator does not need to log out/in when Streambot changes the map.

## User settings

Authenticated cloud users have durable settings stored in PostgreSQL. Currently supported:

- `language` (default: `en`)

Endpoints:

```text
GET /api/v1/user/settings
PUT /api/v1/user/settings
```

Example update:

```json
{
  "language": "de"
}
```

`GET /api/v1/me` also includes the resolved `language`.

## Streambot PIN registration

Registration is initiated by the local Streambot and verified by a human-visible PIN.

1. The cloud panel user logs in normally through `/auth/login` and keeps `/ws/user` connected.
2. Streambot calls `POST /api/v1/streambot/registration/start` with `{"name":"My Streambot","twitch_login":"channelname"}`.
3. Cloud stores the pending registration in Valkey for 30 seconds and sends the six-digit PIN only to that Twitch user's `/ws/user` connections.
4. The panel shows the PIN. The user types it into the local Streambot admin panel.
5. Streambot calls `POST /api/v1/streambot/registration/verify` with `{"pairing_id":"...","pin":"123456"}`.
6. Cloud creates the durable `streambot_instances` record and returns the one-time-visible permanent instance token.

The PIN is never returned from the registration start endpoint, is never stored in PostgreSQL, expires after 30 seconds, and is limited to five verification attempts.

## Cached remote dashboard

The remote dashboard is owner/mod accessible and uses Valkey as the state cache. Supported sections are:

- `music`
- `giveaway`
- `interactions`
- `auto_macros`
- `macros`
- `channel_points`
- `rotating_scene`
- `audio`
- `obs`
- `yolobox`

Streambot can publish all cached sections at once:

```json
{"type":"dashboard_snapshot","data":{"music":{},"giveaway":{},"interactions":[],"auto_macros":[],"macros":[],"channel_points":[],"rotating_scene":{},"audio":{},"obs":{},"yolobox":{}}}
```

or update one section:

```json
{"type":"dashboard_update","section":"music","data":{"playing":true,"title":"..."}}
```

The legacy `snapshot`/`state` message still writes `panel_state` and additionally copies recognized dashboard sections into the section cache.

Panel endpoints (cloud session cookie required; owners and current Valkey moderators are allowed):

- `GET /api/v1/panel/instances`
- `GET /api/v1/panel/instances/:id/dashboard`
- `GET /api/v1/panel/instances/:id/dashboard/:section`
- `POST /api/v1/panel/instances/:id/dashboard/:section`
- `GET /api/v1/panel/instances/:id/yolobox/preview`

A section action body is:

```json
{"action":"play","payload":{}}
```

and is forwarded to Streambot as `type: "dashboard_action"` with `section`, `action`, `payload`, `request_id` and `requested_by`.

### Yolobox preview

Streambot may push a small still preview over the authenticated websocket:

```json
{"type":"yolobox_preview","mime":"image/jpeg","data":"<base64>"}
```

JPEG, WebP and PNG are accepted, max 2 MB. The decoded image is kept in Valkey for 30 seconds and served from `/api/v1/panel/instances/:id/yolobox/preview`. This is intended for periodically refreshed still previews, not a full video stream.

## Native Streambot snapshot support

The cloud accepts Streambot's native websocket payload:

```json
{"type":"snapshot","data":{"dashboard":{...}}}
```

`data.dashboard` is the canonical remote-panel cache source. Supported dashboard sections are cached separately in Valkey. Macro task bodies are intentionally stripped before caching/exposing to remote users; macro controls only need the macro name. The user websocket receives `dashboard_invalidated` when cached dashboard data changes.

## Instance dashboard WebSocket protocol

The remote instance dashboard is WebSocket-only via `GET /ws/user` using the cloud session cookie. Dashboard state and controls are not exposed through REST routes.

Server notifications:
- `notify_instances_update`
- `notify_instance_presence`
- `notify_dashboard_snapshot`
- `notify_dashboard_update`
- `notify_dashboard_action_accepted`
- `notify_yolobox_preview`
- `notify_error`

Client messages:
- `{"type":"request_instances"}`
- `{"type":"request_dashboard","instance_id":"<uuid>"}`
- `{"type":"request_dashboard_section","instance_id":"<uuid>","section":"music"}`
- `{"type":"dashboard_action","instance_id":"<uuid>","section":"music","action":"play","payload":{},"request_id":"<optional uuid>"}`
- `{"type":"request_yolobox_preview","instance_id":"<uuid>"}`

Streambot dashboard snapshots/updates are still cached in Valkey. The WebSocket server reads from that cache and pushes current values directly; the panel never performs an HTTP dashboard fetch.

## Web panel transport

After `/auth/login` creates the browser session, the remote panel uses only `GET /ws/user` for application data and controls. Panel REST endpoints for profile, settings, streamer/instance management, moderator state, dashboard state and dashboard actions are intentionally not registered.

The socket automatically emits bootstrap notifications:

- `notify_user_update`
- `notify_user_settings_update`
- `notify_streamers_update`
- `notify_instances_update`
- pending `streambot_registration` PIN events

Client request/action messages include:

- `request_user`
- `request_user_settings`
- `update_user_settings` (`language`)
- `request_streamers`
- `request_instances`
- `request_streamer_instances` (`streamer_id`)
- `create_instance` (`streamer_id`, `name`)
- `delete_instance` (`instance_id`)
- `request_dashboard` (`instance_id`)
- `request_dashboard_section` (`instance_id`, `section`)
- `dashboard_action` (`instance_id`, `section`, `action`, `payload`, optional `request_id`)
- `request_yolobox_preview` (`instance_id`)

Authentication/OAuth/logout, the Twitch one-time token exchange, health, Streambot registration start/verify/status and the authenticated Streambot machine websocket remain HTTP/machine-facing where appropriate.

## Realtime remote panel contract

`/ws/user` is push-first. On connection the server immediately sends the current user,
settings, streamer access, instance list, cached dashboard snapshots for every accessible
instance, cached Yolobox preview frames when present, and pending registration PINs.
There are no normal `request_*`/reload messages for panel data. Streambot state changes
are pushed as `notify_dashboard_snapshot`, `notify_dashboard_update`,
`notify_yolobox_preview`, and `notify_instance_presence` events.

The browser normally sends only mutations/actions such as `update_user_settings`,
`create_instance`, `delete_instance`, and `dashboard_action`. `resync` exists only as a
recovery/debug mechanism; reconnecting the websocket performs a complete bootstrap.

## Realtime user WebSocket notification contract

The authenticated web panel is realtime-first. `/ws/user` sends current state on connect and every meaningful state mutation emits an explicit `notify_*` message. Normal UI code should not poll or expose reload buttons.

Notable notifications include:

- `notify_user_update`
- `notify_user_settings_update`
- `notify_streamers_update`
- `notify_instances_update`
- `notify_instance_created`

Creation notification order for `create_instance`:

```text
notify_instance_created
notify_instances_update   # freshly rebuilt canonical list
```

The frontend may use `notify_instance_created` for immediate feedback, but must treat the following `notify_instances_update` as authoritative.

- `notify_instance_presence`
- `notify_instance_access_granted`
- `notify_instance_access_revoked`
- `notify_moderators_update`
- `notify_streambot_registration`
- `notify_dashboard_snapshot`
- `notify_dashboard_update`
- `notify_yolobox_preview`
- `notify_dashboard_action_accepted`
- `notify_dashboard_action_result`
- `notify_error`

Streambot may return action completion over `/ws/streambot` as either `dashboard_action_result` or `action_result`, carrying `request_id`, optional `section`/`action`, `success`, `data`, and `error`. The cloud forwards it to authorized panel viewers as `notify_dashboard_action_result`.

## Dashboard layouts in user settings

Cloud user settings now contain both the locale and the remote-dashboard layouts:

```json
{
  "language": "de",
  "dashboard_layouts": {
    "<instance-uuid>": {
      "order": ["music", "interactions", "macros"],
      "hidden": ["giveaway"]
    }
  }
}
```

`dashboard_layouts` is intentionally stored as an opaque JSON object. The remote frontend owns the exact per-instance layout schema and behavior (ordering, visibility and reset), while the cloud persists and synchronizes it between sessions/devices.

Panel updates are WebSocket-only:

```json
{
  "type": "update_user_settings",
  "dashboard_layouts": {
    "<instance-uuid>": {
      "order": ["music", "interactions", "macros"],
      "hidden": ["giveaway"]
    }
  }
}
```

`language` and `dashboard_layouts` are independently optional, but at least one setting must be included. Successful changes emit `notify_user_settings_update` with the complete current settings object to all open panel sessions for that Twitch user.

## Per-instance panel WebSocket

The remote panel now uses two authenticated browser WebSockets:

- `GET /ws/user` for user/global state: profile, settings, streamer/instance list,
  registration and access changes.
- `GET /ws/instance/{instance_id}` for one instance's realtime state and actions.

Opening an instance socket immediately emits:

```json
{"type":"connected","scope":"instance","instance_id":"..."}
```

followed by the current `notify_dashboard_snapshot` and, when cached, a
`notify_yolobox_preview`.

Subsequent StreamDing instance updates are delivered only on that instance
socket, including:

- `notify_dashboard_snapshot`
- `notify_dashboard_update`
- `notify_yolobox_preview`
- `notify_instance_presence`
- `notify_moderators_update`
- `notify_dashboard_action_result`

Dashboard actions must be sent on the matching instance socket:

```json
{
  "type":"dashboard_action",
  "section":"music",
  "action":"next",
  "payload":{},
  "request_id":"optional-uuid"
}
```

The instance id is taken from the WebSocket URL, so clients do not send an
`instance_id` in each action anymore. Access is checked before upgrade and
again for every action. When moderator access is revoked, the user's instance
notification channel is detached immediately.

Each connected instance panel socket owns an independent Tokio task and mpsc
send queue. This isolates slow/noisy instance traffic instead of multiplexing
all dashboard traffic through `/ws/user`.

## Instance liveness

Streambot websocket liveness is intentionally strict:

- the cloud sends a websocket ping every 10 seconds,
- an instance is disconnected after 25 seconds without any websocket response/message,
- the Valkey `streambot:{instance_id}:online` safety key has a 30 second TTL,
- clean disconnects and heartbeat timeouts delete the online key immediately and emit `notify_instance_presence` with `online:false`.

## Ko-fi webhook integration

Ko-fi configuration is owner-only and is managed over `/ws/user`.

Save/update:

```json
{
  "type": "save_kofi_settings",
  "streamer_id": "<streamer uuid>",
  "verification_token": "<Ko-fi verification token>",
  "relay_urls": ["https://example.com/hooks/kofi", "http://hooks.example.net/kofi"]
}
```

The verification token is required when enabling Ko-fi the first time and can be omitted on later relay-only edits. Ko-fi can only be enabled when the owner has at least one registered StreamDing instance. Moderators cannot configure it.

Delete:

```json
{"type":"delete_kofi_settings","streamer_id":"<streamer uuid>"}
```

The panel receives `notify_kofi_settings_update` on connect and after every change. The response contains the generated public webhook URL but never returns the verification token.

Ko-fi should POST to the generated URL `/webhooks/kofi/{webhook_id}`. Valid Ko-fi events are verified, deduplicated by `message_id`, stripped of `verification_token`, then sent to all currently connected instances owned by that streamer as:

```json
{
  "type": "notify_kofi_event",
  "streamer_id": "<streamer uuid>",
  "received_at": "...",
  "data": { "type": "Donation", "...": "..." }
}
```

Optional third-party relay URLs receive the sanitized Ko-fi event using Ko-fi-compatible `application/x-www-form-urlencoded` with the event JSON in the `data` field. Relay URLs are owner-managed, may use HTTP or HTTPS, are limited to 10 entries, and localhost/private/link-local literal targets are rejected. Hostnames are not DNS-resolved for validation, so split-DNS/public hostnames remain supported.

## Ko-fi generated webhook URL

For every owner/streamer with at least one linked streamer-owned instance, `/ws/user`
automatically ensures a persistent Ko-fi integration row exists. The initial
`notify_kofi_settings_update` therefore already contains a stable generated URL before
the verification token is saved:

```json
{
  "type": "notify_kofi_settings_update",
  "integrations": [
    {
      "streamer_id": "...",
      "webhook_id": "...",
      "webhook_url": "https://cloud.streamding.dev/webhooks/kofi/<uuid>",
      "configured": false,
      "verification_token_configured": false,
      "relay_urls": []
    }
  ]
}
```

Saving `verification_token` activates the existing generated URL instead of replacing it.
