# SPDX-FileCopyrightText: 2026 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0

# Include explicitly from BoardConfig.mk when ready to use this policy.
ifndef SPRD_SEPOLICY_INCLUDED
SPRD_SEPOLICY_INCLUDED := true
SPRD_SEPOLICY_PATH := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))

BOARD_VENDOR_SEPOLICY_DIRS += $(SPRD_SEPOLICY_PATH)/base/vendor
SYSTEM_EXT_PUBLIC_SEPOLICY_DIRS += $(SPRD_SEPOLICY_PATH)/base/public
SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += $(SPRD_SEPOLICY_PATH)/base/private

# Real sysfs paths depend on the SoC and kernel device tree.
ifneq ($(strip $(SPRD_SEPOLICY_PLATFORM)),)
ifeq ($(filter $(SPRD_SEPOLICY_PLATFORM),ums9621),)
$(error Unsupported SPRD_SEPOLICY_PLATFORM: $(SPRD_SEPOLICY_PLATFORM))
endif
BOARD_VENDOR_SEPOLICY_DIRS += $(SPRD_SEPOLICY_PATH)/platform/$(SPRD_SEPOLICY_PLATFORM)/vendor
endif

ifneq ($(TARGET_BUILD_VARIANT),user)
BOARD_VENDOR_SEPOLICY_DIRS += $(SPRD_SEPOLICY_PATH)/debug/vendor
SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += $(SPRD_SEPOLICY_PATH)/debug/private
endif
endif
