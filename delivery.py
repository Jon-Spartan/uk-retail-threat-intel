"""Private, durable webhook outbox with atomic claims."""

import hashlib
import logging
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests


MAX_ATTEMPTS = 4


def destination_key(webhook):
    return hashlib.sha256(webhook.encode("utf-8")).hexdigest()


def connect(path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    database = sqlite3.connect(path, timeout=5)
    database.execute("""
        CREATE TABLE IF NOT EXISTS deliveries (
            destination TEXT NOT NULL,
            event_key TEXT NOT NULL,
            message TEXT,
            expires_at REAL NOT NULL,
            next_try_at REAL NOT NULL,
            state TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (destination, event_key)
        )
    """)
    database.execute("""
        CREATE TABLE IF NOT EXISTS migrations (
            name TEXT PRIMARY KEY
        )
    """)
    return database


def import_legacy_deliveries(database, destination, delivered, pending, now):
    with database:
        inserted = database.execute("INSERT OR IGNORE INTO migrations(name) VALUES ('legacy-v1')").rowcount
        if not inserted:
            return
        database.executemany(
            "INSERT OR IGNORE INTO deliveries(destination,event_key,expires_at,next_try_at,state)"
            " VALUES (?,?,?,?, 'sent')",
            ((destination, key, now, now) for key in delivered),
        )
        enqueue(database, destination, pending, now)


def enqueue(database, destination, events, now):
    database.executemany(
        "INSERT OR IGNORE INTO deliveries(destination,event_key,message,expires_at,next_try_at,state)"
        " VALUES (?,?,?,?,?,'queued')",
        ((destination, key, message, expiry, now) for key, message, expiry in events if expiry > now),
    )


def claim(database, destination, now):
    with database:
        database.execute("BEGIN IMMEDIATE")
        database.execute(
            "UPDATE deliveries SET state='expired',message=NULL WHERE state='queued' AND expires_at<=?",
            (now,),
        )
        row = database.execute(
            "SELECT event_key,message,attempts,expires_at FROM deliveries"
            " WHERE destination=? AND state='queued' AND next_try_at<=?"
            " ORDER BY next_try_at,event_key NOT LIKE 'flash:%',event_key LIMIT 1", (destination, now),
        ).fetchone()
        if row is not None:
            database.execute(
                "UPDATE deliveries SET state='sending',attempts=attempts+1 WHERE destination=? AND event_key=?",
                (destination, row[0]),
            )
    return row


def retry_delay(value, now):
    if value:
        if value.isascii() and value.isdecimal() and len(value) <= 10:
            return max(60, int(value))
        try:
            stamp = parsedate_to_datetime(value)
            if stamp.tzinfo is not None:
                return max(60, stamp.timestamp() - now)
        except (TypeError, ValueError, OverflowError, OSError):
            pass
    return 60


def post_notification(webhook, message, now):
    try:
        response = requests.post(webhook, json={"text": message}, timeout=(3, 10), allow_redirects=False)
    except requests.exceptions.ConnectTimeout:
        logging.warning("Webhook connection timed out before delivery.")
        return "queued", 60
    except requests.exceptions.RequestException:
        logging.warning("Webhook delivery is uncertain. Automatic resending suppressed.")
        return "uncertain", 0
    if 200 <= response.status_code < 300:
        return "sent", 0
    logging.warning("Webhook returned HTTP %d.", response.status_code)
    if response.status_code == 429:
        return "queued", retry_delay(response.headers.get("Retry-After"), now)
    if response.status_code == 408 or response.status_code >= 500:
        return "uncertain", 0
    return "rejected", 0


def queue_outbox(path, webhook, events, now, legacy=None):
    destination = destination_key(webhook)
    with closing(connect(path)) as database:
        if legacy is not None and not database.execute(
            "SELECT 1 FROM migrations WHERE name='legacy-v1'"
        ).fetchone():
            delivered, pending = legacy()
            import_legacy_deliveries(database, destination, delivered, pending, now)
        with database:
            enqueue(database, destination, events, now)


def deliver_outbox(path, webhook, clock=None):
    clock = clock or (lambda: datetime.now(timezone.utc).timestamp())
    destination = destination_key(webhook)
    with closing(connect(path)) as database:
        for _ in range(3):
            now = clock()
            event = claim(database, destination, now)
            if event is None:
                break
            event_key, message, prior_attempts, expires_at = event
            state, delay = post_notification(webhook, message, now)
            if state == "queued" and (prior_attempts + 1 >= MAX_ATTEMPTS or now + delay >= expires_at):
                state = "expired"
            with database:
                database.execute(
                    "UPDATE deliveries SET state=?,next_try_at=?,message=? WHERE destination=? AND event_key=?",
                    (state, now + delay, message if state == "queued" else None, destination, event_key),
                )
            if state == "queued":
                break
