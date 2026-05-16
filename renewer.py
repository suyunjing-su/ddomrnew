from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import secrets
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple

import requests
from requests.exceptions import RequestException

UTC = timezone.utc


class DnsheApiError(Exception):
    def __init__(
        self,
        message: str,
        code: str,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.details = details or {}


@dataclass
class AccountConfig:
    name: str
    api_key: str
    api_secret: str
    base_url: str = "https://api005.dnshe.com/index.php"
    enabled: bool = True
    timeout_seconds: int = 20


@dataclass
class RuntimeSettings:
    accounts: List[AccountConfig]
    renewal_threshold_days: int = 7
    attempt_when_unknown: bool = False
    allowed_statuses: Tuple[str, ...] = ("active",)
    mask_sensitive_logs: bool = False
    per_page: int = 200
    request_interval_seconds: float = 0.2
    max_retries: int = 2
    retry_backoff_seconds: float = 1.0


class DnsheClient:
    def __init__(self, account: AccountConfig, settings: RuntimeSettings) -> None:
        self.account = account
        self.settings = settings
        self.account_log_name = to_account_log_name(account.name, settings.mask_sensitive_logs)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-API-Key": account.api_key,
                "X-API-Secret": account.api_secret,
                "Accept": "application/json",
            }
        )

    def _request(
        self,
        method: str,
        endpoint: str,
        action: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        query = {"m": "domain_hub", "endpoint": endpoint}
        if action:
            query["action"] = action
        if params:
            query.update({k: v for k, v in params.items() if v is not None})

        last_error: Optional[Exception] = None
        for attempt in range(self.settings.max_retries + 1):
            try:
                response = self.session.request(
                    method=method,
                    url=self.account.base_url,
                    params=query,
                    json=payload,
                    timeout=self.account.timeout_seconds,
                )
                return self._parse_response(response)
            except RequestException as err:
                last_error = err
            except ValueError as err:
                last_error = err

            if attempt < self.settings.max_retries:
                wait_seconds = self.settings.retry_backoff_seconds * (attempt + 1)
                logging.warning(
                    "[%s] request failed, retrying in %.1fs: %s",
                    self.account_log_name,
                    wait_seconds,
                    last_error,
                )
                time.sleep(wait_seconds)

        raise RuntimeError(f"[{self.account_log_name}] request failed: {last_error}")

    def _parse_response(self, response: requests.Response) -> Dict[str, Any]:
        try:
            data = response.json()
        except ValueError as err:
            if self.settings.mask_sensitive_logs:
                raise ValueError(
                    f"[{self.account_log_name}] invalid JSON response"
                ) from err
            text_sample = response.text[:200]
            raise ValueError(
                f"[{self.account_log_name}] invalid JSON response: {text_sample}"
            ) from err

        if not isinstance(data, dict):
            raise ValueError(f"[{self.account_log_name}] unexpected response payload")

        if not response.ok or data.get("success") is False:
            error_code = str(data.get("error_code") or f"http_{response.status_code}")
            message = str(data.get("message") or data.get("error") or "Unknown API error")
            raise DnsheApiError(
                message=message,
                code=error_code,
                status_code=response.status_code,
                details=data.get("details") if isinstance(data.get("details"), dict) else None,
            )

        return data

    def iter_subdomains(self, per_page: int) -> Iterator[Dict[str, Any]]:
        page = 1
        while True:
            data = self._request(
                method="GET",
                endpoint="subdomains",
                action="list",
                params={"page": page, "per_page": per_page},
            )
            records = data.get("subdomains", [])
            if not isinstance(records, list):
                raise ValueError(f"[{self.account_log_name}] subdomains should be a list")

            for record in records:
                if isinstance(record, dict):
                    yield record

            pagination = data.get("pagination") if isinstance(data.get("pagination"), dict) else {}
            has_more = pagination.get("has_more")

            if has_more is None:
                if len(records) < per_page:
                    break
            elif not bool(has_more):
                break

            if not records:
                break

            page += 1

    def renew_subdomain(self, subdomain_id: int) -> Dict[str, Any]:
        return self._request(
            method="POST",
            endpoint="subdomains",
            action="renew",
            payload={"subdomain_id": subdomain_id},
        )


def is_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def parse_api_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def get_domain_name(subdomain: Dict[str, Any]) -> str:
    full_domain = str(subdomain.get("full_domain") or "").strip()
    if full_domain:
        return full_domain
    left = str(subdomain.get("subdomain") or "").strip()
    right = str(subdomain.get("rootdomain") or "").strip()
    if left and right:
        return f"{left}.{right}"
    if right:
        return right
    if left:
        return left
    return "unknown-domain"


def to_log_token(prefix: str, raw: str) -> str:
    text = str(raw).strip() or "unknown"
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}-{digest}"


def to_account_log_name(account_name: str, mask_sensitive_logs: bool) -> str:
    if not mask_sensitive_logs:
        return account_name
    return to_log_token("acct", account_name)


def to_domain_log_name(
    domain_name: str,
    subdomain_id: Optional[int],
    mask_sensitive_logs: bool,
    alias_map: Dict[str, str],
) -> str:
    if not mask_sensitive_logs:
        return domain_name

    alias_key = domain_name
    if subdomain_id is not None:
        alias_key = f"id:{subdomain_id}"

    existing = alias_map.get(alias_key)
    if existing:
        return existing

    while True:
        alias = f"domain-{secrets.token_hex(5)}"
        if alias not in alias_map.values():
            alias_map[alias_key] = alias
            return alias


def normalize_statuses(value: Any, fallback: Tuple[str, ...]) -> Tuple[str, ...]:
    if value is None:
        return fallback

    items: List[str] = []
    if isinstance(value, str):
        text = value.replace(";", ",").replace("\n", ",")
        items = [segment.strip().lower() for segment in text.split(",")]
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            text = str(item).strip().lower()
            if text:
                items.append(text)
    else:
        text = str(value).strip().lower()
        if text:
            items = [text]

    if not items:
        return fallback

    # Keep order while removing duplicates.
    return tuple(dict.fromkeys(items))


def is_in_free_renew_window(
    subdomain: Dict[str, Any],
    now_utc: datetime,
    threshold_days: int,
    attempt_when_unknown: bool,
) -> Tuple[bool, str]:
    for key in (
        "in_free_renew_window",
        "free_renew_available",
        "free_renewable",
        "can_free_renew",
        "can_renew_now",
        "renewal_available",
        "is_renewable",
    ):
        if key in subdomain:
            value = subdomain.get(key)
            if value is None:
                continue
            flag = is_truthy(value)
            return flag, f"{key}={str(flag).lower()}"

    for key in (
        "free_renew_start_at",
        "free_renewal_start_at",
        "renewal_available_at",
        "renew_available_at",
    ):
        value = parse_api_datetime(subdomain.get(key))
        if value is None:
            continue
        if now_utc >= value:
            return True, f"{key}=reached"
        return False, f"{key}=pending"

    remaining_days = None
    remaining_days_key = ""
    for key in (
        "free_renew_remaining_days",
        "renewal_remaining_days",
        "remaining_days",
        "days_remaining",
        "remaining",
        "days_left",
    ):
        value = to_int(subdomain.get(key))
        if value is not None:
            remaining_days = value
            remaining_days_key = key
            break

    if remaining_days is not None:
        return remaining_days <= threshold_days, f"{remaining_days_key}={remaining_days}"

    expires_at = parse_api_datetime(subdomain.get("expires_at"))
    if expires_at is not None:
        seconds_left = (expires_at - now_utc).total_seconds()
        days_left = int(seconds_left // 86400)
        in_window = 0 <= seconds_left <= threshold_days * 86400
        return in_window, f"days_left={days_left}"

    return attempt_when_unknown, "missing_free_window_fields"


def should_attempt_renew(
    subdomain: Dict[str, Any],
    now_utc: datetime,
    threshold_days: int,
    allowed_statuses: Tuple[str, ...],
    attempt_when_unknown: bool,
) -> Tuple[bool, str]:
    if is_truthy(subdomain.get("never_expires")):
        return False, "never_expires"

    status = str(subdomain.get("status") or "").strip().lower()
    if not status:
        return False, "status=unknown"

    if status not in allowed_statuses:
        return False, f"status={status}"

    return is_in_free_renew_window(
        subdomain=subdomain,
        now_utc=now_utc,
        threshold_days=threshold_days,
        attempt_when_unknown=attempt_when_unknown,
    )


def process_account(
    account: AccountConfig,
    settings: RuntimeSettings,
    dry_run: bool,
) -> Dict[str, Any]:
    account_log_name = to_account_log_name(account.name, settings.mask_sensitive_logs)
    stats: Dict[str, Any] = {
        "account": account_log_name,
        "domains_total": 0,
        "renew_candidates": 0,
        "renewed": 0,
        "not_due": 0,
        "not_yet_available": 0,
        "failed": 0,
        "errors": [],
    }

    if not account.enabled:
        logging.info("[%s] skipped, account disabled", account_log_name)
        return stats

    client = DnsheClient(account, settings)
    now_utc = datetime.now(UTC)
    domain_alias_map: Dict[str, str] = {}

    try:
        for subdomain in client.iter_subdomains(settings.per_page):
            stats["domains_total"] += 1
            subdomain_id = to_int(subdomain.get("id"))
            domain_name = get_domain_name(subdomain)
            domain_log_name = to_domain_log_name(
                domain_name,
                subdomain_id,
                settings.mask_sensitive_logs,
                domain_alias_map,
            )

            if subdomain_id is None:
                stats["failed"] += 1
                stats["errors"].append(f"missing id for {domain_log_name}")
                continue

            should_renew, reason = should_attempt_renew(
                subdomain=subdomain,
                now_utc=now_utc,
                threshold_days=settings.renewal_threshold_days,
                allowed_statuses=settings.allowed_statuses,
                attempt_when_unknown=settings.attempt_when_unknown,
            )
            domain_ref = domain_log_name
            if not settings.mask_sensitive_logs:
                domain_ref = f"{domain_log_name} (id={subdomain_id})"

            if not should_renew:
                stats["not_due"] += 1
                logging.info(
                    "[%s] skip %s (reason=%s)",
                    account_log_name,
                    domain_ref,
                    reason,
                )
                continue

            stats["renew_candidates"] += 1
            if dry_run:
                logging.info(
                    "[%s] dry-run renew candidate %s (reason=%s)",
                    account_log_name,
                    domain_ref,
                    reason,
                )
                continue

            try:
                renew_data = client.renew_subdomain(subdomain_id)
                stats["renewed"] += 1
                logging.info(
                    "[%s] renewed %s (new_expires_at=%s, charged_amount=%s)",
                    account_log_name,
                    domain_ref,
                    renew_data.get("new_expires_at"),
                    renew_data.get("charged_amount"),
                )
            except DnsheApiError as err:
                if err.code == "renewal_not_yet_available":
                    stats["not_yet_available"] += 1
                    logging.info(
                        "[%s] not yet renewable %s",
                        account_log_name,
                        domain_ref,
                    )
                else:
                    stats["failed"] += 1
                    if settings.mask_sensitive_logs:
                        error_line = (
                            f"renew failed for {domain_ref} ("
                            f"code={err.code}, status={err.status_code})"
                        )
                    else:
                        error_line = (
                            f"renew failed for {domain_ref} ("
                            f"code={err.code}, message={err})"
                        )
                    stats["errors"].append(error_line)
                    logging.error("[%s] %s", account_log_name, error_line)

            if settings.request_interval_seconds > 0:
                time.sleep(settings.request_interval_seconds)
    except Exception as err:  # noqa: BLE001
        stats["failed"] += 1
        stats["errors"].append(f"account processing failed: {err}")
        logging.exception("[%s] account processing failed", account_log_name)

    return stats


def normalize_config(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, list):
        return {"accounts": raw}
    if isinstance(raw, dict):
        return raw
    raise ValueError("config must be a JSON object or array")


def load_raw_config(config_path: str) -> Dict[str, Any]:
    env_json = os.getenv("DNSHE_ACCOUNTS_JSON", "").strip()
    if env_json:
        return normalize_config(json.loads(env_json))

    with open(config_path, "r", encoding="utf-8") as fp:
        return normalize_config(json.load(fp))


def env_bool(name: str, fallback: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return fallback
    text = raw.strip()
    if not text:
        return fallback
    return is_truthy(text)


def env_int(name: str, fallback: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return fallback
    text = raw.strip()
    if not text:
        return fallback
    value = to_int(text)
    if value is None:
        raise ValueError(f"invalid integer env {name}")
    return value


def env_float(name: str, fallback: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return fallback
    text = raw.strip()
    if not text:
        return fallback
    return float(text)


def load_settings(config_path: str) -> RuntimeSettings:
    raw = load_raw_config(config_path)

    accounts_raw = raw.get("accounts")
    if not isinstance(accounts_raw, list) or not accounts_raw:
        raise ValueError("accounts must be a non-empty array")

    accounts: List[AccountConfig] = []
    for i, item in enumerate(accounts_raw):
        if not isinstance(item, dict):
            raise ValueError(f"accounts[{i}] must be object")
        name = str(item.get("name") or f"account-{i + 1}").strip()
        api_key = str(item.get("api_key") or "").strip()
        api_secret = str(item.get("api_secret") or "").strip()
        if not api_key or not api_secret:
            raise ValueError(f"accounts[{i}] missing api_key or api_secret")

        account = AccountConfig(
            name=name,
            api_key=api_key,
            api_secret=api_secret,
            base_url=str(item.get("base_url") or "https://api005.dnshe.com/index.php").strip(),
            enabled=is_truthy(item.get("enabled", True)),
            timeout_seconds=to_int(item.get("timeout_seconds")) or 20,
        )
        accounts.append(account)

    defaults = RuntimeSettings(accounts=accounts)
    default_mask_sensitive_logs = is_truthy(os.getenv("GITHUB_ACTIONS", ""))
    allowed_statuses = normalize_statuses(
        raw.get("allowed_statuses"),
        defaults.allowed_statuses,
    )
    allowed_statuses = normalize_statuses(
        os.getenv("DNSHE_ALLOWED_STATUSES"),
        allowed_statuses,
    )
    renewal_threshold_days = env_int(
        "DNSHE_RENEW_THRESHOLD_DAYS",
        to_int(raw.get("renewal_threshold_days")) or defaults.renewal_threshold_days,
    )
    if renewal_threshold_days < 0:
        renewal_threshold_days = 0

    return RuntimeSettings(
        accounts=accounts,
        renewal_threshold_days=renewal_threshold_days,
        attempt_when_unknown=env_bool(
            "DNSHE_ATTEMPT_WHEN_UNKNOWN",
            is_truthy(raw.get("attempt_when_unknown", defaults.attempt_when_unknown)),
        ),
        allowed_statuses=allowed_statuses,
        mask_sensitive_logs=env_bool(
            "DNSHE_MASK_SENSITIVE_LOGS",
            is_truthy(raw.get("mask_sensitive_logs", default_mask_sensitive_logs)),
        ),
        per_page=env_int("DNSHE_PER_PAGE", to_int(raw.get("per_page")) or defaults.per_page),
        request_interval_seconds=env_float(
            "DNSHE_REQUEST_INTERVAL_SECONDS",
            float(raw.get("request_interval_seconds", defaults.request_interval_seconds)),
        ),
        max_retries=env_int(
            "DNSHE_MAX_RETRIES",
            to_int(raw.get("max_retries")) or defaults.max_retries,
        ),
        retry_backoff_seconds=env_float(
            "DNSHE_RETRY_BACKOFF_SECONDS",
            float(raw.get("retry_backoff_seconds", defaults.retry_backoff_seconds)),
        ),
    )


def parse_hhmm(text: str) -> Tuple[int, int]:
    parts = text.strip().split(":")
    if len(parts) != 2:
        raise ValueError("run time format must be HH:MM")
    hour = int(parts[0])
    minute = int(parts[1])
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        raise ValueError("run time must be in 24h clock")
    return hour, minute


def next_run_utc(now_utc: datetime, run_time: str, tz_offset_hours: int) -> datetime:
    hour, minute = parse_hhmm(run_time)
    run_tz = timezone(timedelta(hours=tz_offset_hours), name=f"UTC{tz_offset_hours:+d}")
    local_now = now_utc.astimezone(run_tz)
    local_target = local_now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if local_now >= local_target:
        local_target += timedelta(days=1)
    return local_target.astimezone(UTC)


def run_once(settings: RuntimeSettings, dry_run: bool) -> int:
    all_stats = []
    total_failed = 0

    for account in settings.accounts:
        account_stats = process_account(account, settings, dry_run)
        all_stats.append(account_stats)
        total_failed += int(account_stats.get("failed", 0))

    for item in all_stats:
        logging.info(
            "[summary:%s] total=%s candidates=%s renewed=%s not_due=%s not_yet_available=%s failed=%s",
            item["account"],
            item["domains_total"],
            item["renew_candidates"],
            item["renewed"],
            item["not_due"],
            item["not_yet_available"],
            item["failed"],
        )
        errors = item.get("errors")
        if isinstance(errors, list):
            for line in errors:
                logging.error("[summary:%s] %s", item["account"], line)

    return 1 if total_failed > 0 else 0


def run_daemon(
    settings: RuntimeSettings,
    run_time: str,
    tz_offset_hours: int,
    dry_run: bool,
) -> int:
    while True:
        now_utc = datetime.now(UTC)
        planned_utc = next_run_utc(now_utc, run_time, tz_offset_hours)
        wait_seconds = max(1, int((planned_utc - now_utc).total_seconds()))
        logging.info(
            "next run at %s (target timezone UTC%+d %s)",
            planned_utc.isoformat(),
            tz_offset_hours,
            run_time,
        )
        time.sleep(wait_seconds)
        exit_code = run_once(settings, dry_run)
        if exit_code != 0:
            return exit_code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DNSHE multi-account auto-renew runner",
    )
    parser.add_argument(
        "--config",
        default="config/accounts.json",
        help="Path to JSON config, ignored when DNSHE_ACCOUNTS_JSON is set",
    )
    parser.add_argument(
        "--mode",
        choices=["once", "daemon"],
        default=os.getenv("DNSHE_MODE", "once"),
        help="Run once or keep daemon scheduler",
    )
    parser.add_argument(
        "--run-time",
        default=os.getenv("DNSHE_RUN_TIME", "09:00"),
        help="Daily run time in HH:MM for target timezone",
    )
    parser.add_argument(
        "--tz-offset",
        type=int,
        default=env_int("DNSHE_TZ_OFFSET", 8),
        help="Target timezone offset hours, UTC+8 means 8",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print renew candidates without sending renew requests",
    )
    return parser.parse_args()


def configure_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main() -> int:
    configure_logging()
    args = parse_args()

    try:
        settings = load_settings(args.config)
    except Exception as err:  # noqa: BLE001
        logging.error("load settings failed: %s", err)
        return 2

    if args.mode == "daemon":
        return run_daemon(
            settings=settings,
            run_time=args.run_time,
            tz_offset_hours=args.tz_offset,
            dry_run=args.dry_run,
        )

    return run_once(settings=settings, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
