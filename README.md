# REST API Logger

Logs every WordPress REST API request — route, method, status, duration, IP and user — so you can see exactly who is hitting your API, which endpoints are slow, and where the errors come from.

## Features

- **Full request log** — method, route, HTTP status, duration in ms, client IP and the user (or guest) for every real REST request.
- **Tools → REST API Log viewer** — filter by method, success/error status and route substring; 50 entries per page.
- **Errors-only mode** — optionally log only responses with status ≥ 400, keeping the table small on busy sites.
- **Excluded routes** — one substring per line (e.g. a noisy health-check route); matching routes are never logged.
- **Admin-user toggle** — optionally skip requests made by administrators.
- **Retention pruning** — a daily WP-Cron job deletes rows older than the retention window (default 30 days).
- **Safe by design** — logging hooks into `rest_pre_dispatch` / `rest_post_dispatch` only; internal `rest_do_request()` sub-requests are not logged, and the log write never changes the response.

## Installation

1. Upload the `wp-rest-api-logger` folder to `/wp-content/plugins/`.
2. Activate the plugin through **Plugins** in WordPress admin.
3. View the log under **Tools → REST API Log**.

## Uninstall

Deleting the plugin drops the `wral_logs` table, removes the `wral_settings` option and clears the daily pruning cron.

## License

MIT — see [LICENSE](LICENSE).
