"""Проверка валидности cookie kleinanzeigen.de."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx

CHECK_URL = "https://www.kleinanzeigen.de/m-meine-anzeigen.html"
LOGIN_PATHS = ("/m-einloggen", "login.kleinanzeigen.de", "/u/login", "/oidc/")
AUTH_MARKERS = ("m-meine-anzeigen", "meine anzeigen", "ausloggen", "m-nachrichten")
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
HTTP_TIMEOUT = 15.0
MS_THRESHOLD = 1e11
MAX_REDIRECTS = 5


@dataclass
class Cookie:
    name: str
    value: str
    domain: str
    path: str = "/"
    expires: float | None = None
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None

    def is_expired(self) -> bool:
        if self.expires is None:
            return False
        return time.time() > self.expires

    @property
    def expires_human(self) -> str:
        if self.expires is None:
            return "session"
        return datetime.fromtimestamp(self.expires, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )


@dataclass
class CheckResult:
    status: str
    reason: str = ""
    http_code: int | None = None
    final_url: str | None = None
    cookies: list[Cookie] = field(default_factory=list)


def load_cookies_from_bytes(raw_bytes: bytes) -> list[Cookie]:
    data = json.loads(raw_bytes.decode("utf-8"))
    if isinstance(data, dict) and "cookies" in data:
        data = data["cookies"]
    if not isinstance(data, list):
        raise ValueError("Ожидался список объектов с куками")

    cookies: list[Cookie] = []
    for item in data:
        if not isinstance(item, dict) or "name" not in item or "value" not in item:
            continue
        raw_exp = item.get("expires") or item.get("expirationDate")
        expires: float | None = None
        if raw_exp is not None:
            try:
                expires = float(raw_exp)
            except (TypeError, ValueError):
                expires = None
            if expires is not None and expires > MS_THRESHOLD:
                expires /= 1000.0

        cookies.append(Cookie(
            name=str(item["name"]),
            value=str(item["value"]),
            domain=str(item.get("domain") or ".kleinanzeigen.de"),
            path=str(item.get("path") or "/"),
            expires=expires,
            secure=bool(item.get("secure", False)),
            http_only=bool(item.get("httpOnly", False)),
            same_site=item.get("sameSite"),
        ))
    if not cookies:
        raise ValueError("В файле не найдено ни одной куки")
    return cookies


def _domain_matches(cookie_domain: str, host: str) -> bool:
    d = cookie_domain.lstrip(".").lower()
    h = host.lower()
    return h == d or h.endswith("." + d)


def _path_matches(cookie_path: str, req_path: str) -> bool:
    if not cookie_path:
        return True
    if req_path == cookie_path:
        return True
    return req_path.startswith(cookie_path.rstrip("/") + "/")


def _live_for_request(cookies: list[Cookie], url: str) -> list[Cookie]:
    parsed = urlparse(url)
    host = (parsed.hostname or "www.kleinanzeigen.de").lower()
    req_path = parsed.path or "/"
    now = time.time()
    live = []
    for c in cookies:
        if c.expires is not None and c.expires <= now:
            continue
        if not _domain_matches(c.domain, host):
            continue
        if not _path_matches(c.path, req_path):
            continue
        live.append(c)
    return live


def check_cookies(cookies: list[Cookie]) -> CheckResult:
    live = _live_for_request(cookies, CHECK_URL)
    if not live:
        return CheckResult(
            status="expired",
            reason="Нет живых кук для домена/пути запроса",
            cookies=cookies,
        )

    cookie_header = "; ".join(f"{c.name}={c.value}" for c in live)
    headers = {
        "User-Agent": USER_AGENT,
        "Accept-Language": "de-DE,de;q=0.9,en;q=0.8",
        "Accept": "text/html,*/*;q=0.8",
        "Cookie": cookie_header,
    }

    current_url = CHECK_URL
    with httpx.Client(
        timeout=HTTP_TIMEOUT,
        follow_redirects=False,
        headers=headers,
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            try:
                r = client.get(current_url)
            except httpx.RequestError as e:
                return CheckResult(
                    status="unknown",
                    reason=f"Сетевая ошибка: {e}",
                    cookies=cookies,
                )

            location = r.headers.get("location", "")
            final_url = urljoin(str(r.url), location) if location else str(r.url)

            if r.is_redirect and any(p in location.lower() for p in LOGIN_PATHS):
                return CheckResult(
                    status="unauthorized",
                    reason=f"Редирект на логин: {location}",
                    http_code=r.status_code,
                    final_url=final_url,
                    cookies=cookies,
                )

            if r.status_code in (401, 403):
                return CheckResult(
                    status="unauthorized",
                    reason="Сервер отклонил авторизацию",
                    http_code=r.status_code,
                    final_url=final_url,
                    cookies=cookies,
                )

            if r.status_code == 200:
                text_lower = r.text[:200_000].lower()
                if "einloggen" in text_lower and "passwort" in text_lower:
                    return CheckResult(
                        status="unauthorized",
                        reason="Сервер вернул страницу логина (код 200)",
                        http_code=200,
                        final_url=final_url,
                        cookies=cookies,
                    )
                if any(m in text_lower for m in AUTH_MARKERS):
                    return CheckResult(
                        status="valid",
                        reason="Сессия активна, найден маркер авторизации",
                        http_code=200,
                        final_url=final_url,
                        cookies=cookies,
                    )
                return CheckResult(
                    status="unknown",
                    reason="HTTP 200, но маркеры авторизации не найдены",
                    http_code=200,
                    final_url=final_url,
                    cookies=cookies,
                )

            if r.is_redirect:
                current_url = final_url
                continue

            return CheckResult(
                status="unknown",
                reason=f"Неожиданный HTTP-код {r.status_code}",
                http_code=r.status_code,
                final_url=final_url,
                cookies=cookies,
            )

    return CheckResult(
        status="unknown",
        reason="Слишком много редиректов",
        cookies=cookies,
    )
