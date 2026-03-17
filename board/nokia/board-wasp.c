//
// SPDX-FileCopyrightText: 2025 Roger Ortiz <me@r0rt1z2.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <board_ops.h>

#define VOLUME_UP 17

static void handle_recovery_boot(void) {
    if (get_bootmode() != BOOTMODE_RECOVERY || !is_spoofing_enabled())
        return;

    printf("Recovery boot detected, modifying cmdline for unlocked state.\n");
    /*cmdline_replace((char *)0x480B68C8, "androidboot.verifiedbootstate=",
                    "green", "orange");*/
}

static void spoof_lock_state(void) {
    uint32_t addr = 0;

    // LK has two security gates in the fastboot command processor that
    // reject commands with "not support on security" and "not allowed
    // in locked state" errors. When spoofing lock state, these would
    // block all fastboot operations despite the device being actually
    // unlocked underneath.
    //
    // Even without spoofing, we patch these out as a safety measure
    // since OEM-specific checks could still interfere with fastboot
    // commands in unexpected ways.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0x4B65, 0x4C66, 0xE92D, 0x4880);
    if (addr) {
        printf("Found fastboot command processor at 0x%08X\n", addr);

        // "not support on security" call
        NOP(addr + 0x182, 2);

        // "not allowed in locked state" call
        NOP(addr + 0x18E, 2);

        // Jump directly to command handler
        PATCH_MEM(addr + 0x10C, 0xE005);
    }

    int spoofing = is_spoofing_enabled();
    fastboot_publish("is-spoofing", spoofing ? "1" : "0");

    if (!spoofing) {
        printf("Bootloader lock status spoofing disabled.\n");
        return;
    }

    printf("Bootloader lock status spoofing enabled, applying patches.\n");

    // On most MediaTek devices, lock state is fetched by calling
    // seccfg_get_lock_state() directly. Some vendors (e.g. Xiaomi)
    // add a wrapper that also checks a custom lock mechanism, but
    // this device does not have one.
    //
    // Unlike other LK images that route all callers through a b.w
    // thunk (which can be redirected with a single patch), this LK
    // calls seccfg_get_lock_state() directly, so we patch the
    // function body itself. The patch forces it to store 1 into the
    // output parameter and return 2, which the caller interprets as
    // the unlocked state.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB1D0, 0xB510, 0x4604, 0xF7FF, 0xFFDD);
    if (addr) {
        printf("Found seccfg_get_lock_state at 0x%08X\n", addr);
        PATCH_MEM(addr + 6,
                  0x2301,  // movs r3, #1
                  0x6023,  // str r3, [r4, #0]
                  0x2002,  // movs r0, #2
                  0xbd10   // pop {r4, pc}
        );
    }

    // AVB adds device state info to the kernel cmdline, but it
    // keeps showing "unlocked" even when we want it to say "locked".
    // This patch forces the cmdline to always use the "locked"
    // string instead of checking the actual device state.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x4FF0, 0xB0A9, 0xF101);
    if (addr) {
        printf("Found AVB cmdline function at 0x%08X\n", addr);

        // NOP out the code that checks the actual device state,
        // forcing libavb to always use the "locked" string.
        NOP(addr + 0x9C, 4);
    }

    // AVB verifies vbmeta public keys in two places: once for the main
    // vbmeta image (validate_vbmeta_public_key) and once for chained
    // vbmeta images (avb_safe_memcmp against the expected key). Both
    // reject the boot if the key doesn't match, causing the "Public key
    // used to sign data rejected" error. We patch both checks so any
    // key is accepted regardless.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0x429A, 0xF000, 0x817A);
    if (addr) {
        printf("Found load_and_verify_vbmeta at 0x%08X\n", addr);

        // Change "cmp r2, r3" to "cmp r3, r3" so the chain key
        // length check always succeeds.
        PATCH_MEM(addr, 0x451B);

        // NOP the bne.w that rejects mismatched chained vbmeta keys.
        NOP(addr + 0x308, 2);

        // Replace "cmp r3, #0" with "movs r3, #1" so key_is_trusted
        // is always nonzero.
        PATCH_MEM(addr + 0x37A, 0x2301);
    }

    // When booting into recovery, we need to ensure verifiedbootstate
    // is set to "orange" so fastbootd detects the device as unlocked
    // and allows flashing. We also patch a few other cmdline params
    // (secureboot, device_state) as a precaution in case stock
    // recovery checks them as well.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF00B, 0xFB7F, 0xF000, 0xFECF);
    if (addr) {
        printf("Found cmdline_pre_process at 0x%08X\n", addr);
        //PATCH_CALL(addr, (void *)handle_recovery_boot, TARGET_THUMB);
    }
}

void board_early_init(void) {
    printf("Entering early init for Nokia 2.2\n");

    uint32_t addr = 0;

    // Regardless of whether spoofing is enabled, we always need to
    // disable image authentication. The user may just be using this
    // custom LK to unlock their device, or they may be spoofing
    // where the locked state would enforce verification.
    //
    // Forcing get_vfy_policy to return 0 skips certificate
    // verification for all partitions and firmware images (boot,
    // recovery, dtbo, SCP, etc.) so the device can boot with
    // modified or unsigned images.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0xF7FF, 0xFF75, 0xF3C0);
    if (addr) {
        printf("Found get_vfy_policy at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // Allow erasing and flashing partitions while locked
    addr = SEARCH_PATTERN(LK_START, LK_END, 0x4A2F, 0xAD04, 0x4623, 0x4628, 0x2140);
    if (addr) {
        printf("Found format not allowed at 0x%08X\n", addr);

        // Branch to format handler
        PATCH_MEM(addr, 0xE7B6);
    }

    addr = SEARCH_PATTERN(LK_START, LK_END, 0x4A26, 0xAC06, 0x4633, 0x4620, 0x2140);
    if (addr) {
        printf("Found download not allowed at 0x%08X\n", addr);

        // Branch to download handler
        PATCH_MEM(addr, 0xE757);
    }

    // The environment area isn't initialized yet when board_early_init
    // runs, so any get_env calls would return NULL at this stage. We
    // hook a printf call in platform_init that runs right after env
    // initialization completes, it's a convenient entry point since
    // the call itself is non-essential and we need the env to be ready
    // before applying our lock state patches.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF02D, 0xF91C, 0x6823, 0x4638);
    if (addr) {
        printf("Found env_init_done at 0x%08X\n", addr);
        PATCH_CALL(addr, (void*)spoof_lock_state, TARGET_THUMB);
    }

    fastboot_register("oem bldr_spoof", cmd_spoof_bootloader_lock, 0);
}

void board_late_init(void) {
    printf("Entering late init for Nokia 2.2\n");

    uint32_t addr = 0;

    // Suppresses the bootloader unlock warning shown during boot on
    // unlocked devices. In addition to the visual warning, it also
    // introduces an unnecessary 5-second delay.
    // 
    // This patch gets rid of the delay and the warning by forcing the
    // function that holds the logic to always return 0 and therefore
    // not executing the code that shows the warning.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0x4B0E, 0x447B);
    if (addr) {
        printf("Found orange_state_warning at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // Disables the warning shown during boot when the device is unlocked and
    // the dm-verity state is corrupted. This behaves like the previous lock
    // state warnings, visual only, with no real impact.
    //
    // Same approach: patch the function to always return 0.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0x2802, 0xD000, 0x4770);
    if (addr) {
        printf("Found dm_verity_corruption at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }

    // Huaqin removed the option to enter recovery mode on wasp by
    // volume up, the only ways to enter recovery mode is via adb
    // and fastboot, making our lives harder.
    //
    // The 2 lines of code below will re-enable that functionality.
    if (mtk_detect_key(VOLUME_UP))
        set_bootmode(BOOTMODE_RECOVERY);
}
