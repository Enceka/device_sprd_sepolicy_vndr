#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
"""Compile SPRD policy without editing BoardConfig or invoking a device build."""

import argparse
import ctypes
import ctypes.util
import json
import re
import subprocess
import tempfile
from pathlib import Path


ORDER = (
    "security_classes", "initial_sids", "access_vectors", "global_macros",
    "neverallow_macros", "mls_macros", "mls_decl", "mls", "policy_capabilities",
    "te_macros", "attributes", "ioctl_defines", "ioctl_macros", "*.te",
    "roles_decl", "roles", "users", "initial_sid_contexts", "fs_use",
    "genfs_contexts", "port_contexts",
)


def run(args, output=None):
    if output is None:
        subprocess.run([str(x) for x in args], check=True)
    else:
        with output.open("w") as stream:
            subprocess.run([str(x) for x in args], stdout=stream, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--android-root", type=Path, default=Path.cwd())
    parser.add_argument("--variant", choices=("user", "userdebug", "eng"), default="user")
    parser.add_argument("--platform", choices=("ums9621",))
    parser.add_argument("--vendor-policy", type=Path, action="append", default=[],
                        help="additional vendor policy directory; may be repeated")
    parser.add_argument("--recovery", action="store_true")
    parser.add_argument("--legacy-debugfs", action="store_true",
                        help="also check the pre-Android-12 launch-device branch")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--avc-summary", type=Path,
                        help="also check entrypoint labels for captured init transition failures")
    args = parser.parse_args()
    root = args.android_root.resolve()
    repo = Path(__file__).resolve().parents[1]
    policy = root / "system/sepolicy"
    extra_vendor = list(dict.fromkeys(directory.resolve() for directory in args.vendor_policy))
    for directory in extra_vendor:
        if not directory.is_dir():
            parser.error(f"Vendor policy directory does not exist: {directory}")
    host = root / "out/host/linux-x86/bin"
    m4 = root / "prebuilts/build-tools/linux-x86/bin/m4"
    for tool in (m4, host / "checkpolicy", host / "secilc", host / "checkfc",
                 host / "check_prop_prefix", host / "sepolicy-analyze"):
        if not tool.is_file():
            parser.error(f"Missing host tool: {tool}; build SELinux host tools first")
    if args.output:
        output = args.output.resolve()
        output.mkdir(parents=True, exist_ok=True)
    else:
        output = Path(tempfile.mkdtemp(prefix="sprd-sepolicy-check."))

    public = [repo / "base/public"]
    private = [repo / "base/private"]
    vendor = [repo / "base/vendor"]
    if args.platform:
        vendor.append(repo / f"platform/{args.platform}/vendor")
    if args.variant != "user":
        private.append(repo / "debug/private")
        vendor.append(repo / "debug/vendor")
    vendor = list(dict.fromkeys([*vendor, *extra_vendor]))
    checked_vendor = vendor.copy()
    # Include the independent Lineage policy if this is a Lineage checkout.
    lineage = root / "device/lineage/sepolicy/common"
    if lineage.is_dir():
        public.append(lineage / "public")
        private.append(lineage / "private")
        vendor.extend((lineage / "dynamic", lineage / "vendor"))

    # Match policyConf's recovery settings in system/sepolicy/build/soong/policy.go.
    # Recovery is a monolithic policy; applying normal split-policy restrictions
    # produces failures in AOSP recovery/fastbootd rules before SPRD is checked.
    split = "false" if args.recovery else "true"
    defines = {
        "mls_num_sens": "1", "mls_num_cats": "1024", "target_arch": "arm64",
        "target_with_asan": "false", "target_with_dexpreopt": "true",
        "target_with_native_coverage": "false", "target_build_variant": args.variant,
        "target_full_treble": split, "target_compatible_property": split,
        "target_treble_sysprop_neverallow": split, "target_enforce_sysprop_owner": split,
        "target_exclude_build_test": "false",
        "target_requires_insecure_execmem_for_swiftshader": "false",
        "target_enforce_debugfs_restriction": "false" if args.legacy_debugfs else "true",
        "target_recovery": "true" if args.recovery else "false",
    }
    flags = [m4, "--fatal-warnings"]
    for key, value in defines.items():
        flags.extend(("-D", f"{key}={value}"))
    flags.append("-s")

    def expand(dirs, name):
        sources = [p for pattern in ORDER for directory in dirs
                   for p in sorted(directory.glob(pattern)) if p.is_file()]
        conf = output / f"{name}.conf"
        run([*flags, *sources], conf)
        return conf

    # These separate builds catch accidental use of vendor-only types in
    # system_ext, and private platform types in vendor policy.
    split_builds = (
        ("vendor", [policy / "reqd_mask", policy / "public", *public,
                    policy / "vendor", *vendor]),
        ("system_ext", [policy / "public", policy / "private", *public, *private]),
    ) if not args.recovery else ()
    for name, dirs in split_builds:
        conf = expand(dirs, name)
        run([host / "checkpolicy", "-M", "-C", "-c", "30", "-o",
             output / f"{name}.cil", conf])
        print(f"PASS {name}: syntax and partition symbol visibility", flush=True)

    conf = expand([policy / "public", policy / "private", *public, *private,
                   policy / "vendor", *vendor], "combined")
    cil = output / "combined.cil"
    run([host / "checkpolicy", "-M", "-C", "-c", "30", "-o", cil, conf])
    if not args.recovery:
        with cil.open("a") as stream:
            stream.write("\n" + (policy / "private/technical_debt.cil").read_text())
    binary = output / "sepolicy"
    # Neverallows stay enabled, including checks after CIL attribute expansion.
    run([host / "secilc", "-m", "-M", "true", "-G", "-c", "30", cil,
         "-o", binary, "-f", output / "compiled_file_contexts"])
    print("PASS combined: compile and neverallows", flush=True)

    context_dirs = [policy / "private", policy / "vendor", *public, *private, *vendor]
    for name, option in (("file_contexts", None), ("property_contexts", "-p"),
                         ("service_contexts", "-s"), ("hwservice_contexts", "-l")):
        sources = [d / name for d in context_dirs if (d / name).is_file()]
        dest = output / name
        run([*flags, *sources], dest)
        run([host / "checkfc", *([option] if option else []), binary, dest])
        print(f"PASS {name}: syntax and context types", flush=True)
    if args.avc_summary:
        check_captured_transitions(args.avc_summary, output / "file_contexts", cil, args.variant)
    vendor_properties = output / "vendor_property_contexts"
    run([*flags, *(directory / "property_contexts" for directory in checked_vendor
                   if (directory / "property_contexts").is_file())], vendor_properties)
    run([host / "check_prop_prefix", "--property-contexts", vendor_properties,
         "--allowed-property-prefix", "vendor.", "persist.vendor.", "ro.vendor.",
         "ctl.start$vendor.", "ctl.stop$vendor.", "ctl.restart$vendor.",
         "--allowed-context-prefix", "vendor_", "--strict"])
    result = subprocess.run([str(host / "sepolicy-analyze"), str(binary), "permissive"],
                            check=True, capture_output=True, text=True)
    sprd_permissive = [x for x in result.stdout.splitlines()
                      if "sprd" in x or x == "vendor_yloglite"]
    if sprd_permissive:
        raise SystemExit(f"Unexpected SPRD permissive domains: {sprd_permissive}")
    print(f"PASS vendor property namespaces and SPRD enforcing domains; output: {output}")
    print("Offline validation only; device boot, AVC coverage, mapping/version tests and CTS remain.")


def check_captured_transitions(summary, contexts, cil, variant):
    """Use libselinux's actual regex matching, then check init's CIL transitions."""
    library = ctypes.util.find_library("selinux")
    if not library:
        raise SystemExit("--avc-summary requires host libselinux")
    selinux = ctypes.CDLL(library, use_errno=True)
    libc = ctypes.CDLL(ctypes.util.find_library("c"))

    class Option(ctypes.Structure):
        _fields_ = [("type", ctypes.c_int), ("value", ctypes.c_char_p)]

    selinux.selabel_open.argtypes = [ctypes.c_uint, ctypes.POINTER(Option), ctypes.c_uint]
    selinux.selabel_open.restype = ctypes.c_void_p
    selinux.selabel_lookup_raw.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                         ctypes.c_char_p, ctypes.c_int]
    selinux.selabel_lookup_raw.restype = ctypes.c_int
    selinux.selabel_close.argtypes = [ctypes.c_void_p]
    libc.free.argtypes = [ctypes.c_void_p]
    option = Option(3, str(contexts).encode())
    handle = selinux.selabel_open(0, ctypes.byref(option), 1)
    if not handle:
        raise SystemExit(f"libselinux failed to open {contexts}")
    transitions = set(re.findall(r"\(typetransition init (\w+) process (\w+)\)", cil.read_text()))
    debug_only = {"engpc", "dcxsrv", "srtd", "systemDebuggerd"}
    checked = skipped = 0
    try:
        for path in json.loads(summary.read_text())["missing_domain_transitions"]:
            if variant == "user" and Path(path).name in debug_only:
                skipped += 1
                continue
            context = ctypes.c_void_p()
            result = selinux.selabel_lookup_raw(handle, ctypes.byref(context), path.encode(), 0o100755)
            if result != 0:
                raise SystemExit(f"Missing executable label: {path}")
            try:
                label = ctypes.string_at(context).decode().split(":")[2]
            finally:
                libc.free(context)
            if not any(exec_type == label for exec_type, _ in transitions):
                raise SystemExit(f"No init transition for {path}: {label}")
            checked += 1
    finally:
        selinux.selabel_close(handle)
    print(f"PASS captured init failures: {checked} executable labels/transitions; "
          f"{skipped} debug-only executables excluded", flush=True)


if __name__ == "__main__":
    main()
