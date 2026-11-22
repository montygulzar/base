from app.modules.discord_id import snowflake_to_date, SNOWFLAKE_RE
from app.modules.discord_mentions import _looks_like_snowflake
from app.api.ingest import classify


def test_snowflake_regex():
    assert SNOWFLAKE_RE.match("167348773909528576")
    assert SNOWFLAKE_RE.match("12345678901234567890")
    assert not SNOWFLAKE_RE.match("1234")
    assert not SNOWFLAKE_RE.match("abc1234567890")


def test_snowflake_decode_known():
    # Snowflake 0 decodes exactly to Discord's epoch (2015-01-01 UTC).
    d = snowflake_to_date("0")
    assert d["created_at"].startswith("2015-01-01")
    assert d["created_at_unix_ms"] == 1_420_070_400_000
    # A real mid-2016 id should decode to 2016.
    d2 = snowflake_to_date("167348773909528576")
    assert d2["created_at"].startswith("2016")
    assert d2["created_at_unix_ms"] > 1_420_070_400_000


def test_snowflake_plausibility_filter():
    assert _looks_like_snowflake("167348773909528576")
    # Clearly too old: snowflake 0 decodes to Discord epoch (2015-01-01) — plausible
    assert _looks_like_snowflake("0")
    # Random 19-digit non-snowflake that would decode to year 50000+
    assert not _looks_like_snowflake("9" * 20)


def test_classify_picks_discord_snowflake():
    c = classify("167348773909528576")
    assert c == ("discord", "167348773909528576")


def test_classify_picks_discord_invite():
    c = classify("https://discord.gg/abcDEF")
    assert c == ("url", "https://discord.gg/abcDEF")
    c2 = classify("discord.gg/xyz-123")
    assert c2 == ("url", "discord.gg/xyz-123")
