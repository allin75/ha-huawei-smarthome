# MateTV Pro V0FP adaptation

Scope approved on 2026-09-26: add EDIS-770A as a TV media player, validate
screen on/off and actual reported state, then pair as a separate HomeKit TV
accessory. Leave the existing light bridge unchanged. No volume or input
controls until physical behavior is verified.

The production discovery snapshot contains 48 services, including screen and
devicestate. The public Profile contains only three. switch.on remains 1 while
screenState is 0, so it must not determine power state.

Implementation: a product-specific adapter reads devicestate.screenState;
screen.on boolean is the initial candidate command based on other TV adapters.
Missing screen service removes controls. Offline reports mark the entity
unavailable. Acknowledgments never change local state, and failures propagate
without trying unrelated fields. Generic media players honor device_class
metadata so this model can be exported as a HomeKit television.

Validation order: synthetic regression tests, production-runtime imports and
tests in staging, publish commit, back up and overlay the three target code
files, reload/restart integration, compare real screen state, test screen off
and on with the owner, then create a separate HomeKit accessory if successful.
Cloud ACK alone is insufficient. Physical power control is pending.

Rollback restores the previous media_player.py and manifest.json and removes
the new product adapter. Preserve account sessions, other adapters and the
paired light bridge. Do not publish real device IDs, credentials or snapshots.
