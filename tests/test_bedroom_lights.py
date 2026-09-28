"""Independent product contracts using synthetic lighting data."""

import importlib
import unittest
from unittest.mock import AsyncMock

PRODUCTS = ("ZG0U", "ZG0V", "ZG0W", "ZG0X")


class Context:
    def __init__(self, pid, value=0, method="RW"):
        self.prod_id = pid
        self.profile = {
            "services": [
                {
                    "serviceId": "switch",
                    "characteristics": [
                        {
                            "characteristicName": "on",
                            "characteristicType": "bool",
                            "method": method,
                            "enumList": [{"enumVal": 0}, {"enumVal": 1}],
                        }
                    ],
                }
            ]
        }
        self.raw = value
        self.async_send_service = AsyncMock()

    def value(self, sid, key):
        assert (sid, key) == ("switch", "on")
        return self.raw


class BedroomLightsTests(unittest.IsolatedAsyncioTestCase):
    def adapter(self, pid):
        return importlib.import_module(
            f"custom_components.huawei_smarthome.device_adapters.prod_{pid}"
        ).ADAPTER

    def test_actual_profile_contract_and_unknown_state(self):
        for pid in PRODUCTS:
            for raw, expected in [
                (0, False),
                ("0", False),
                (1, True),
                ("1", True),
                (None, None),
                ("bad", None),
                (2, None),
            ]:
                with self.subTest(pid=pid, raw=raw):
                    ctx = Context(pid, raw)
                    (spec,) = self.adapter(pid).entities(ctx)
                    self.assertEqual(spec.platform, "light")
                    self.assertEqual(
                        spec.state(ctx), {"is_on": expected, "color_mode": "onoff"}
                    )
                    self.assertEqual(spec.metadata["supported_color_modes"], {"onoff"})

    def test_identity_and_write_permissions(self):
        for pid in PRODUCTS:
            adapter = self.adapter(pid)
            self.assertEqual(adapter.entities(Context("unrelated")), ())
            self.assertEqual(adapter.entities(Context(pid, method="R")), ())
            ctx = Context(pid)
            ctx.profile = {}
            self.assertEqual(adapter.entities(ctx), ())
            self.assertEqual(len(adapter.entities(Context(pid.lower()))), 1)

    async def test_exact_commands_and_no_optimistic_state(self):
        for pid in PRODUCTS:
            ctx = Context(pid)
            (spec,) = self.adapter(pid).entities(ctx)
            await spec.actions["turn_on"](ctx, {})
            ctx.async_send_service.assert_awaited_once_with("switch", {"on": 1})
            self.assertIs(spec.state(ctx)["is_on"], False)
            ctx.async_send_service.reset_mock()
            await spec.actions["turn_off"](ctx, {})
            ctx.async_send_service.assert_awaited_once_with("switch", {"on": 0})

    async def test_unsupported_controls_and_rejected_commands(self):
        for pid in PRODUCTS:
            ctx = Context(pid)
            (spec,) = self.adapter(pid).entities(ctx)
            for data in [
                {"brightness": 0},
                {"color_temp_kelvin": 3000},
                {"rgb_color": (1, 2, 3)},
            ]:
                with self.assertRaises(ValueError):
                    await spec.actions["turn_on"](ctx, data)
            ctx.async_send_service.assert_not_awaited()
            ctx.async_send_service.side_effect = RuntimeError("synthetic rejection")
            with self.assertRaises(RuntimeError):
                await spec.actions["turn_off"](ctx, {})
            self.assertEqual(ctx.async_send_service.await_count, 1)


if __name__ == "__main__":
    unittest.main()
