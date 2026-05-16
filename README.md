# DNSHE Auto Renew (Multi-Account)

每天按 UTC+8 的 09:00 检查 DNSHE 账户下子域名是否进入可续期窗口，满足条件后自动调用续期接口。

## Features

- Multi-account processing
- Daily schedule support with fixed timezone offset (UTC+8)
- Pagination for subdomain list
- Renew requests are sent only when a domain is inside the free renewal window
- Strict status filtering with allowlist (default `active` only)
- Sensitive account/subdomain identifiers are masked in GitHub Actions logs
- GitHub Actions schedule (`01:00 UTC` = `09:00 UTC+8`)
- After each workflow run, `run.time` is updated on `main`

## Requirements

- Python 3.10+
- `pip install -r requirements.txt`

## Local Run

1. Edit `config/accounts.json` with your account list.
2. Run one-shot mode:

```bash
python renewer.py --mode once
```

3. Run daemon scheduler mode (daily 09:00 at UTC+8):

```bash
python renewer.py --mode daemon --run-time 09:00 --tz-offset 8
```

4. Dry run:

```bash
python renewer.py --mode once --dry-run
```

## Config

Use `config/accounts.example.json` as the schema reference.

Top-level fields:

- `accounts`: account array
- `renewal_threshold_days`: free-window day threshold for fallback fields (default `7`)
- `attempt_when_unknown`: when free-window fields are missing, whether to attempt renew (default `false`)
- `allowed_statuses`: status allowlist for renew candidates (default `["active"]`)
- `per_page`: list page size (default `200`, max `500` by API)
- `request_interval_seconds`: delay between renew requests (default `0.2`)
- `max_retries`: request retry count (default `2`)
- `retry_backoff_seconds`: linear backoff base seconds (default `1.0`)

Account fields:

- `name`
- `api_key`
- `api_secret`
- `enabled` (optional, default `true`)
- `timeout_seconds` (optional, default `20`)

## Environment Overrides

- `DNSHE_ACCOUNTS_JSON`
- `DNSHE_RENEW_THRESHOLD_DAYS`
- `DNSHE_ATTEMPT_WHEN_UNKNOWN`
- `DNSHE_ALLOWED_STATUSES` (comma separated, e.g. `active,suspended`)
- `DNSHE_PER_PAGE`
- `DNSHE_REQUEST_INTERVAL_SECONDS`
- `DNSHE_MAX_RETRIES`
- `DNSHE_RETRY_BACKOFF_SECONDS`
- `DNSHE_MASK_SENSITIVE_LOGS`
- `DNSHE_MODE`
- `DNSHE_RUN_TIME`
- `DNSHE_TZ_OFFSET`
- `LOG_LEVEL`

## GitHub Actions

Workflow file: `.github/workflows/auto-renew.yml`

Set repository secret:

- Secret: `DNSHE_ACCOUNTS_JSON` (required, multi-account JSON)

Tune optional settings in the same JSON payload (top-level fields), or extend workflow env mapping if you prefer GitHub repository variables.

Workflow behavior:

- Workflow sets `DNSHE_MASK_SENSITIVE_LOGS=true`, so CI logs do not print account names, subdomain names, or domain IDs.
- Local run keeps readable logs by default (unless you set `DNSHE_MASK_SENSITIVE_LOGS=true`).
- Workflow writes latest run timestamp into `run.time`.
- If the previous `main` commit is also the bot's `run.time` update commit, workflow squashes it into one commit and force-pushes with lease.
- Normal code commits are never rewritten by this logic.

Example secret payload:

```json
{
  "accounts": [
    {
      "name": "main-account",
      "api_key": "cfsd_xxxxxxxxxx",
      "api_secret": "yyyyyyyyyyyy"
    },
    {
      "name": "backup-account",
      "api_key": "cfsd_zzzzzzzzzz",
      "api_secret": "aaaaaaaaaaaa"
    }
  ],
  "renewal_threshold_days": 7,
  "attempt_when_unknown": false,
  "allowed_statuses": ["active"],
  "mask_sensitive_logs": false
}
```
