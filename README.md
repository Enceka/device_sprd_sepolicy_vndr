# SPRD vendor SELinux policy

Shared UNISOC / Spreadtrum policy for Android 13 / LineageOS 20.

Include from the device's `BoardConfig.mk`:

```make
SPRD_SEPOLICY_PLATFORM := ums9621
include device/sprd/sepolicy_vndr/SEPolicy.mk
```

`base/` contains common vendor and system_ext policy; `platform/ums9621/`
adds platform labels. `debug/` is included only for eng and userdebug builds.
Keep board-specific paths in the device tree's policy directory.

From the Android source root:

```sh
python3 device/sprd/sepolicy_vndr/tools/check_policy.py --platform ums9621 \
    --vendor-policy device/rongyue/e5/sepolicy/vendor --variant user
m selinux_policy sepolicy_tests treble_sepolicy_tests
```

Licensed under Apache-2.0.
