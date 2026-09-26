"""MateTV tests use synthetic reports, never cloud credentials."""

import unittest
from unittest.mock import AsyncMock

from custom_components.huawei_smarthome.device_adapters.prod_V0FP import ADAPTER


class Context:
    available = True

    def __init__(self, value=0, screen=True):
        self.values = {"devicestate": {"screenState": value}, "switch": {"on": "1"}}
        if screen:
            self.values["screen"] = {}
        self.async_send_service = AsyncMock()

    def has_service(self, sid):
        return sid in self.values

    def value(self, sid, key):
        return self.values.get(sid, {}).get(key)


class MateTVTests(unittest.IsolatedAsyncioTestCase):
    def test_reported_panel_state_overrides_switch(self):
        for raw, expected in [(0, "off"), ("0", "off"), (1, "on"), ("1", "on"), (2, None), (None, None), ("bad", None)]:
            with self.subTest(raw=raw):
                ctx = Context(raw)
                spec, = ADAPTER.entities(ctx)
                self.assertEqual(spec.state(ctx), {"state": expected})
                self.assertEqual(spec.metadata["device_class"], "tv")

    def test_offline_and_unknown(self):
        for raw in [2, "2"]:
            ctx = Context(raw)
            self.assertFalse(ADAPTER.entities(ctx)[0].availability(ctx))
        ctx = Context(1)
        ctx.available = False
        self.assertFalse(ADAPTER.entities(ctx)[0].availability(ctx))

    def test_missing_services_do_not_offer_unsupported_controls(self):
        ctx = Context(screen=False)
        self.assertEqual(ADAPTER.entities(ctx)[0].actions, {})
        del ctx.values["devicestate"]
        self.assertEqual(ADAPTER.entities(ctx), ())

    async def test_commands_do_not_fabricate_state_or_retry_other_channels(self):
        ctx = Context()
        spec, = ADAPTER.entities(ctx)
        await spec.actions["turn_on"](ctx, {})
        ctx.async_send_service.assert_awaited_once_with("screen", {"on": True})
        self.assertEqual(spec.state(ctx)["state"], "off")
        ctx.async_send_service.reset_mock()
        await spec.actions["turn_off"](ctx, {})
        ctx.async_send_service.assert_awaited_once_with("screen", {"on": False})
        ctx.async_send_service.reset_mock()
        ctx.async_send_service.side_effect = RuntimeError("rejected")
        with self.assertRaises(RuntimeError):
            await spec.actions["turn_on"](ctx, {})
        self.assertEqual(ctx.async_send_service.await_count, 1)


if __name__ == "__main__":
    unittest.main()
