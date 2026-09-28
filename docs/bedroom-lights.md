# Bedroom lights for Apple Home

User requested all bedroom lights for an iPhone good-night scene. Discovery
identified five unadapted Huawei devices across products ZG0U/V/W/X. All four
public Profiles and runtime reports agree on switch/on with numeric 0/1.
ZG0X already exists upstream but is absent in this NAS installation; reuse it.
Add the other three following the existing independent ZG0R adapter pattern.

Validate Profile write permission, reject unsupported dimming/color commands,
preserve unknown state, and never fabricate state from command ACKs. Product
mappings apply to every matching device; HomeKit export is explicitly limited
to five bedroom lights plus the previously paired KAMAI light. Preserve the TV
accessory and avoid duplicating the Xiaomi bedside lamp's native HomeKit entry.

Validate synthetic failure/state cases and actual HA LightEntity runtime.
Publish the commit, back up production component, configuration and HomeKit
state, overlay four adapters and manifest, restart and verify registration.
Add bedroom entities to the existing bridge. Physical switching and Apple Home
visibility require owner observation. The owner can create an Apple Home scene
named 晚安 that sets all five lights Off. Do not promise dimming or offline use.
