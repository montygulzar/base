"""Correlation unit test against an in-memory sqlite replacement is overkill;
instead we test the pure-python shape of inputs it expects via a tiny stub.
"""
import asyncio
from unittest.mock import AsyncMock
from app.correlation import correlate_investigation


def test_correlation_runs_without_data():
    # Smoke: feed a mock session with empty selects, ensure no exception.
    db = AsyncMock()
    result_empty = AsyncMock()
    result_empty.scalars.return_value.all.return_value = []
    result_empty.first.return_value = None
    db.execute.return_value = result_empty
    db.get.return_value = None
    asyncio.run(correlate_investigation(db, "inv-1"))
    assert db.commit.called
