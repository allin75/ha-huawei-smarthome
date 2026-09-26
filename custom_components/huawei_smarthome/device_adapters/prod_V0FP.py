"""MateTV Pro EDIS-770A: screen power and reported state.

The public Profile is incomplete. The device reports devicestate and screen
services at runtime. screen.on is a candidate power channel shared by other
Huawei TVs; V0FP physical validation is tracked in docs/matetv-validation.md.
Never interpret switch.on or remotecontrol.switchState as panel power, and
never treat a command ACK as a state report. No remote credentials are exposed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .api import EntitySpec

if TYPE_CHECKING:
    from .context import DeviceContext


def _screen_state(context: DeviceContext) -> str | None:
    value = context.value("devicestate", "screenState")
    if value in (0, "0"):
        return "off"
    if value in (1, "1"):
        return "on"
    return None


def _available(context: DeviceContext) -> bool:
    return context.available and context.value("devicestate", "screenState") not in (2, "2")


async def _turn_on(context: DeviceContext, data) -> None:
    await context.async_send_service("screen", {"on": True})


async def _turn_off(context: DeviceContext, data) -> None:
    await context.async_send_service("screen", {"on": False})


class MateTVProAdapter:
    prod_id = "V0FP"

    def entities(self, context: DeviceContext) -> tuple[EntitySpec, ...]:
        if not context.has_service("devicestate"):
            return ()
        actions = {"turn_on": _turn_on, "turn_off": _turn_off} if context.has_service("screen") else {}
        return (EntitySpec(
            platform="media_player", key="television", name="电视",
            state=lambda device: {"state": _screen_state(device)},
            metadata={"device_class": "tv"}, actions=actions,
            availability=_available,
        ),)


ADAPTER = MateTVProAdapter()
