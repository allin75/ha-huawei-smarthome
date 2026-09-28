"""A0MP protocol contracts against the public vendor Profile, no real commands."""

import json
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, call

from custom_components.huawei_smarthome.device_adapters.prod_A0MP import ADAPTER


class Context:
    prod_id = "A0MP"

    def __init__(self):
        self.profile = json.loads(
            (Path(__file__).parent / "fixtures/A0MP.json").read_text()
        )
        self.raw = {
            "switch": {"on": 0},
            "mode": {"mode": 2},
            "temperature": {"target": 25},
            "fan": {"gear": 0},
        }
        self.async_send_service = AsyncMock()

    def value(self, sid, key):
        return self.raw.get(sid, {}).get(key)


class A0MPTests(unittest.IsolatedAsyncioTestCase):
    def test_profile_and_state(self):
        c = Context()
        (s,) = ADAPTER.entities(c)
        self.assertEqual(
            s.metadata["hvac_modes"], ["off", "auto", "cool", "heat", "fan_only", "dry"]
        )
        self.assertEqual(
            (
                s.metadata["min_temp"],
                s.metadata["max_temp"],
                s.metadata["target_temperature_step"],
            ),
            (16, 32, 1),
        )
        self.assertEqual(s.state(c)["hvac_mode"], "off")
        self.assertIsNone(s.state(c)["current_temperature"])
        for value, result in [
            (1, "auto"),
            (2, "cool"),
            (3, "heat"),
            (4, "fan_only"),
            (5, "dry"),
            (100, None),
            (None, None),
        ]:
            c.raw["switch"]["on"] = 1
            c.raw["mode"]["mode"] = value
            self.assertEqual(s.state(c)["hvac_mode"], result)
        c.raw["switch"]["on"] = None
        self.assertIsNone(s.state(c)["hvac_mode"])
        c.raw["temperature"]["target"] = 99
        self.assertIsNone(s.state(c)["target_temperature"])

    def test_identity_and_permissions(self):
        c = Context()
        c.prod_id = "unrelated"
        self.assertEqual(ADAPTER.entities(c), ())
        c = Context()
        c.profile["services"][0]["characteristics"][0]["method"] = "R"
        self.assertEqual(ADAPTER.entities(c), ())
        c = Context()
        c.profile["services"][3]["characteristics"][0]["method"] = "R"
        (s,) = ADAPTER.entities(c)
        self.assertNotIn("set_fan_mode", s.actions)

    async def test_numeric_commands_and_state_not_optimistic(self):
        c = Context()
        (s,) = ADAPTER.entities(c)
        await s.actions["turn_on"](c, {})
        await s.actions["set_temperature"](c, {"temperature": 26})
        await s.actions["set_fan_mode"](c, {"fan_mode": "very_high"})
        await s.actions["set_hvac_mode"](c, {"hvac_mode": "heat"})
        await s.actions["turn_off"](c, {})
        self.assertEqual(
            c.async_send_service.await_args_list,
            [
                call("switch", {"on": 1}),
                call("temperature", {"target": 26}),
                call("fan", {"gear": 5}),
                call("mode", {"mode": 3}),
                call("switch", {"on": 1}),
                call("switch", {"on": 0}),
            ],
        )
        self.assertEqual(s.state(c)["hvac_mode"], "off")
        self.assertEqual(s.state(c)["target_temperature"], 25)

    async def test_invalid_inputs_send_nothing(self):
        c = Context()
        (s,) = ADAPTER.entities(c)
        for v in [None, True, 15, 33, 26.5, float("nan"), float("inf"), "bad"]:
            with self.assertRaises(ValueError):
                await s.actions["set_temperature"](c, {"temperature": v})
        for action, key in [
            ("set_hvac_mode", "hvac_mode"),
            ("set_fan_mode", "fan_mode"),
        ]:
            with self.assertRaises(ValueError):
                await s.actions[action](c, {key: "unsupported"})
        c.async_send_service.assert_not_awaited()

    async def test_mode_failure_never_powers_on_or_retries(self):
        c = Context()
        (s,) = ADAPTER.entities(c)
        c.async_send_service.side_effect = RuntimeError("synthetic rejection")
        with self.assertRaises(RuntimeError):
            await s.actions["set_hvac_mode"](c, {"hvac_mode": "cool"})
        c.async_send_service.assert_awaited_once_with("mode", {"mode": 2})
        self.assertEqual(s.state(c)["hvac_mode"], "off")

    async def test_power_on_failure_propagates_without_fake_state(self):
        c = Context()
        (s,) = ADAPTER.entities(c)
        c.async_send_service.side_effect = [None, RuntimeError("synthetic rejection")]
        with self.assertRaises(RuntimeError):
            await s.actions["set_hvac_mode"](c, {"hvac_mode": "heat"})
        self.assertEqual(c.async_send_service.await_count, 2)
        self.assertEqual(s.state(c)["hvac_mode"], "off")
