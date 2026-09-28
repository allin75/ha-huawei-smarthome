"""Daikin A0MP ducted AC: mappings from the public Huawei product Profile.

No room temperature or compressor activity is reported. Commands never synthesize
state; subsequent device reports are authoritative.
"""

import math

from .api import EntitySpec

MODES = {1: "auto", 2: "cool", 3: "heat", 4: "fan_only", 5: "dry"}
FANS = {0: "auto", 1: "low", 2: "medium", 3: "high", 4: "strong", 5: "very_high"}


def _int(value):
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
        return int(number) if math.isfinite(number) and number.is_integer() else None
    except (TypeError, ValueError, OverflowError):
        return None


def _field(ctx, sid, key):
    for service in (ctx.profile or {}).get("services", ()):
        if service.get("serviceId") == sid:
            return next(
                (
                    f
                    for f in service.get("characteristics", ())
                    if f.get("characteristicName") == key
                ),
                {},
            )
    return {}


def _writable(ctx, sid, key):
    return "W" in _field(ctx, sid, key).get("method", "")


def _choices(ctx, sid, key, known):
    values = {_int(e.get("enumVal")) for e in _field(ctx, sid, key).get("enumList", ())}
    return {v: label for v, label in known.items() if v in values}


async def _send(ctx, sid, key, value):
    field = _field(ctx, sid, key)
    if not _writable(ctx, sid, key):
        raise ValueError("Profile does not permit this command")
    choices = field.get("enumList")
    if choices and value not in {_int(e.get("enumVal")) for e in choices}:
        raise ValueError("Command is not in the product Profile enum")
    await ctx.async_send_service(sid, {key: value})


class ProductA0MPAdapter:
    prod_id = "A0MP"

    def entities(self, ctx):
        if (ctx.prod_id or "").upper() != self.prod_id:
            return ()
        if not all(
            _writable(ctx, sid, key)
            for sid, key in (
                ("switch", "on"),
                ("mode", "mode"),
                ("temperature", "target"),
            )
        ):
            return ()
        modes = _choices(ctx, "mode", "mode", MODES)
        if not modes:
            return ()
        fans = (
            _choices(ctx, "fan", "gear", FANS) if _writable(ctx, "fan", "gear") else {}
        )
        field = _field(ctx, "temperature", "target")
        low, high, step = (_int(field.get(k)) for k in ("min", "max", "step"))
        if (
            low is None
            or high is None
            or step != 1
            or low < 16
            or high > 32
            or low > high
        ):
            return ()

        def state(device):
            power = device.value("switch", "on")
            mode = None
            if power in (0, "0", False):
                mode = "off"
            elif power in (1, "1", True):
                mode = modes.get(_int(device.value("mode", "mode")))
            target = _int(device.value("temperature", "target"))
            return {
                "hvac_mode": mode,
                "target_temperature": target
                if target is not None and low <= target <= high
                else None,
                "current_temperature": None,
                "fan_mode": fans.get(_int(device.value("fan", "gear"))),
            }

        async def on(device, data):
            await _send(device, "switch", "on", 1)

        async def off(device, data):
            await _send(device, "switch", "on", 0)

        async def temperature(device, data):
            value = _int(data.get("temperature"))
            if value is None or not low <= value <= high:
                raise ValueError(
                    "A0MP requires an integer target within the Profile range"
                )
            await _send(device, "temperature", "target", value)

        async def mode(device, data):
            selected = data.get("hvac_mode")
            if selected == "off":
                await off(device, {})
                return
            value = next((v for v, label in modes.items() if label == selected), None)
            if value is None:
                raise ValueError("Unsupported A0MP mode")
            await _send(device, "mode", "mode", value)
            await on(device, {})

        async def fan(device, data):
            value = next(
                (v for v, label in fans.items() if label == data.get("fan_mode")), None
            )
            if value is None:
                raise ValueError("Unsupported A0MP fan speed")
            await _send(device, "fan", "gear", value)

        actions = {
            "turn_on": on,
            "turn_off": off,
            "set_temperature": temperature,
            "set_hvac_mode": mode,
        }
        metadata = {
            "hvac_modes": ["off", *modes.values()],
            "min_temp": low,
            "max_temp": high,
            "target_temperature_step": 1,
        }
        if fans:
            actions["set_fan_mode"] = fan
            metadata["fan_modes"] = list(fans.values())
        return (
            EntitySpec(
                platform="climate",
                key="air_conditioner",
                name="空调",
                state=state,
                actions=actions,
                metadata=metadata,
            ),
        )


ADAPTER = ProductA0MPAdapter()
