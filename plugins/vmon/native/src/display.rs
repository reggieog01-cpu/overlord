//! Virtual display management: stage the embedded Virtual Display Driver
//! (MttVDD, IddCx user-mode driver — signed, legitimate), install it once via
//! pnputil, and attach its display at far-off desktop coordinates so the real
//! user never sees or reaches it.

use std::mem::size_of;
use std::path::PathBuf;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiCallClassInstaller, SetupDiCreateDeviceInfoList, SetupDiCreateDeviceInfoW,
    SetupDiSetDeviceRegistryPropertyW, UpdateDriverForPlugAndPlayDevicesW, DICD_GENERATE_ID,
    DIF_REGISTERDEVICE, GUID_DEVCLASS_DISPLAY, INSTALLFLAG_FORCE, SPDRP_HARDWAREID,
    SP_DEVINFO_DATA,
};
use windows::Win32::Foundation::{CloseHandle, POINTL};
use windows::Win32::Graphics::Gdi::{
    EnumDisplaySettingsW, ENUM_REGISTRY_SETTINGS,
    ChangeDisplaySettingsExW, EnumDisplayDevicesW, CDS_UPDATEREGISTRY, DEVMODEW, DISPLAY_DEVICEW,
    DISPLAY_DEVICE_ACTIVE, DM_BITSPERPEL, DM_DISPLAYFREQUENCY, DM_PELSHEIGHT, DM_PELSWIDTH,
    DM_POSITION,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, WaitForSingleObject, CREATE_NO_WINDOW, PROCESS_INFORMATION,
    STARTUPINFOW,
};

const DRIVER_FILES: [(&str, &[u8]); 4] = [
    ("MttVDD.inf", include_bytes!("../driver/MttVDD.inf")),
    ("MttVDD.dll", include_bytes!("../driver/MttVDD.dll")),
    ("mttvdd.cat", include_bytes!("../driver/mttvdd.cat")),
    ("devcon.exe", include_bytes!("../driver/devcon.exe")),
];

// Publisher certificate for the driver package (SignPath Foundation).
// Pre-seeding it into the Trusted Publishers store makes the pnputil install
// fully silent — otherwise Windows shows a "trust this publisher?" dialog even
// for elevated installs.
const PUBLISHER_CERT: &[u8] = include_bytes!("../driver/signpath.cer");

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Enumerate display devices; returns (DeviceName, DeviceID, active).
fn enum_displays() -> Vec<(String, String, bool)> {
    let mut out = Vec::new();
    for i in 0..128u32 {
        let mut dd = DISPLAY_DEVICEW::default();
        dd.cb = size_of::<DISPLAY_DEVICEW>() as u32;
        let ok = unsafe { EnumDisplayDevicesW(PCWSTR::null(), i, &mut dd, 0) };
        if !ok.as_bool() {
            break;
        }
        out.push((
            wide_to_string(&dd.DeviceName),
            wide_to_string(&dd.DeviceID).to_lowercase(),
            (dd.StateFlags & DISPLAY_DEVICE_ACTIVE).0 != 0,
        ));
    }
    out
}

/// Device name (\\.\DISPLAYn) of the MttVDD virtual display, if present.
pub fn find_virtual_display() -> Option<(String, bool)> {
    enum_displays()
        .into_iter()
        .find(|(_, id, _)| id.contains("mttvdd"))
        .map(|(name, _, active)| (name, active))
}

fn run_hidden(exe: &str, args: &str, wait_ms: u32) -> Result<u32, String> {
    let cmd = format!("{} {}", exe, args);
    let mut cmd_wide = to_wide(&cmd);
    let si = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(cmd_wide.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            PCWSTR::null(),
            &si,
            &mut pi,
        )
        .map_err(|e| format!("spawn {}: {}", exe, e))?;
        WaitForSingleObject(pi.hProcess, wait_ms);
        let mut code = 0u32;
        let _ = GetExitCodeProcess(pi.hProcess, &mut code);
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);
        Ok(code)
    }
}

/// Fallback device creation via cfgmgr32 (what SetupDi wraps, minus its
/// instance-name validation that rejects "Root\MttVDD" on some builds).
fn create_device_node_cm(inf_path: &str) -> Result<(), String> {
    use windows::Win32::Devices::DeviceAndDriverInstallation::{
        CM_Create_DevNodeW, CM_CREATE_DEVINST_GENERATE_ID, CR_SUCCESS,
    };
    unsafe {
        let id = to_wide("Root\\MttVDD");
        let mut devinst: u32 = 0;
        let cr = CM_Create_DevNodeW(&mut devinst, PCWSTR(id.as_ptr()), 0, CM_CREATE_DEVINST_GENERATE_ID);
        if cr != CR_SUCCESS {
            return Err(format!("CM_Create_DevNodeW: {:?}", cr));
        }
        let hwid_ws = to_wide("Root\\MttVDD");
        let inf_ws = to_wide(inf_path);
        let mut reboot = windows::core::BOOL(0);
        UpdateDriverForPlugAndPlayDevicesW(
            None,
            PCWSTR(hwid_ws.as_ptr()),
            PCWSTR(inf_ws.as_ptr()),
            INSTALLFLAG_FORCE,
            Some(&mut reboot),
        )
        .map_err(|e| format!("bind driver: {}", e))?;
        Ok(())
    }
}

/// Create the Root\MttVDD device node and bind the staged driver — the step
/// devcon performs in VDD's own installer (pnputil alone only stages the
/// package into the driver store).
fn create_device_node(inf_path: &str) -> Result<(), String> {
    match try_create_device_node("Root\\MttVDD", inf_path, true) {
        Ok(()) => Ok(()),
        Err(e) => {
            let cm = create_device_node_cm(inf_path);
            if cm.is_err() {
                Err(format!("{}; cm fallback: {}", e, cm.unwrap_err()))
            } else {
                Ok(())
            }
        }
    }
}

/// Variant-exposed for the CLI dev harness. `flags` lets the harness try
/// DICD_GENERATE_ID vs full instance ids.
pub fn try_create_device_node(instance: &str, inf_path: &str, generate_id: bool) -> Result<(), String> {
    unsafe {
        let devs = SetupDiCreateDeviceInfoList(Some(&GUID_DEVCLASS_DISPLAY), None)
            .map_err(|e| format!("SetupDiCreateDeviceInfoList: {}", e))?;
        let mut did = SP_DEVINFO_DATA {
            cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        // devcon passes the setup CLASS NAME ("Display") as DeviceName with
        // DICD_GENERATE_ID — the hardware id only goes into the HardwareID
        // property below. Passing "Root\MttVDD" here is what produced
        // ERROR_INVALID_DEVINST_NAME.
        let class_name = to_wide("Display");
        let desc = to_wide("Virtual Display Driver");
        let flags = if generate_id {
            DICD_GENERATE_ID
        } else {
            windows::Win32::Devices::DeviceAndDriverInstallation::SETUP_DI_DEVICE_CREATION_FLAGS(0)
        };
        SetupDiCreateDeviceInfoW(
            devs,
            PCWSTR(class_name.as_ptr()),
            &GUID_DEVCLASS_DISPLAY,
            PCWSTR(desc.as_ptr()),
            None,
            flags,
            Some(&mut did),
        )
        .map_err(|e| format!("SetupDiCreateDeviceInfoW: {}", e))?;

        // HardwareID is a REG_MULTI_SZ: "<instance>\0\0" (double-terminated).
        let hwid: Vec<u16> = to_wide(instance)
            .into_iter()
            .chain(std::iter::once(0))
            .collect();
        let hwid_bytes =
            std::slice::from_raw_parts(hwid.as_ptr() as *const u8, hwid.len() * 2);
        SetupDiSetDeviceRegistryPropertyW(devs, &mut did, SPDRP_HARDWAREID, Some(hwid_bytes))
            .map_err(|e| format!("set hardware id: {}", e))?;

        SetupDiCallClassInstaller(DIF_REGISTERDEVICE, devs, Some(&did))
            .map_err(|e| format!("register device: {}", e))?;

        let hwid_ws = to_wide(instance);
        let inf_ws = to_wide(inf_path);
        let mut reboot = windows::core::BOOL(0);
        UpdateDriverForPlugAndPlayDevicesW(
            None,
            PCWSTR(hwid_ws.as_ptr()),
            PCWSTR(inf_ws.as_ptr()),
            INSTALLFLAG_FORCE,
            Some(&mut reboot),
        )
        .map_err(|e| format!("bind driver: {}", e))?;
        Ok(())
    }
}

/// Install the driver package if no MttVDD device exists yet.
/// Files are staged to %TEMP% from embedded bytes — nothing is downloaded.
fn umdf_service_ok() -> bool {
    use windows::Win32::System::Registry::{RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ};
    let sub: Vec<u16> = "SYSTEM\\CurrentControlSet\\Services\\MttVDD"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut hkey = HKEY::default();
        let r = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(sub.as_ptr()),
            None,
            KEY_READ,
            &mut hkey,
        );
        r.is_ok()
    }
}

pub fn ensure_driver() -> Result<(), String> {
    let dev_present = find_virtual_display().is_some();
    if dev_present && umdf_service_ok() {
        return Ok(());
    }
    if dev_present {
        // Broken partial install (no UMDF service) - nuke and redo so
        // devcon runs the full DIFx install with the WDF co-installer.
        let _ = run_hidden("pnputil", "/remove-device ROOT\\DISPLAY\\0000", 30_000);
        let _ = run_hidden("pnputil", "/delete-driver oem5.inf /uninstall /force", 30_000);
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    let dir: PathBuf = std::env::temp_dir().join("vmon-drv");
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {}", e))?;
    for (name, bytes) in DRIVER_FILES {
        std::fs::write(dir.join(name), bytes).map_err(|e| format!("write {}: {}", name, e))?;
    }
    // Seed the driver mode table so the display comes up at a proper
    // resolution instead of the 800x600 default.
    let _ = std::fs::create_dir_all(r"C:\VirtualDisplayDriver");
    let _ = std::fs::write(
        r"C:\VirtualDisplayDriver\vdd_settings.xml",
        include_bytes!("../driver/vdd_settings.xml"),
    );
    // Trust the publisher first - suppresses the interactive driver-trust
    // dialog so the install is silent on fresh machines.
    let cert = dir.join("publisher.cer");
    std::fs::write(&cert, PUBLISHER_CERT).map_err(|e| format!("write cert: {}", e))?;
    let _ = run_hidden(
        "certutil",
        &format!("-addstore -f TrustedPublisher \"{}\"", cert.display()),
        30_000,
    );
    let inf = dir.join("MttVDD.inf");
    let inf_str = inf.to_string_lossy().into_owned();
    let _ = run_hidden(
        "pnputil",
        &format!("/add-driver \"{}\" /install", inf_str),
        60_000,
    );
    // Device creation can lag pnputil by a moment.
    for _ in 0..6 {
        if find_virtual_display().is_some() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    // pnputil only stages the package - devcon creates the node AND runs
    // the full DIFx install (including the WDF/UMDF service registration).
    // Poll generously: slow boxes can take half a minute to enumerate the
    // new device, and a rescan nudges it along.
    let devcon = dir.join("devcon.exe");
    let _ = run_hidden(
        &devcon.to_string_lossy(),
        &format!("install \"{}\" Root\\MttVDD", inf_str),
        120_000,
    );
    for i in 0..60 {
        if find_virtual_display().is_some() {
            return Ok(());
        }
        if i == 20 {
            let _ = run_hidden("pnputil", "/scan-devices", 30_000);
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    // Last resort: create the node via SetupAPI and bind the driver directly.
    let _ = create_device_node(&inf_str);
    for _ in 0..30 {
        if find_virtual_display().is_some() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err("driver installed but no MttVDD device appeared".to_string())
}

/// Attach the virtual display at the given desktop coordinates at the
/// requested resolution. Far-off (non-adjacent) coordinates keep it invisible
/// to the user and unreachable by the physical cursor.
/// Returns the display's device name and desktop position (left, top).
pub fn ensure_display_at(width: u32, height: u32, far_x: i32, far_y: i32) -> Result<(String, i32, i32), String> {
    ensure_driver()?;
    let (name, active) =
        find_virtual_display().ok_or_else(|| "no virtual display device".to_string())?;

    if !active {
        // CCD first: builds/activates the path in the display database, which
        // works even when Windows refuses the plain CDS attach. On failure
        // fall back to the CDS retry loop.
        if ccd_attach(width, height, far_x, far_y).is_err() {
            // The IddCx driver needs a moment after device start before its
            // adapter accepts mode sets — retry the attach for up to ~30s.
            let mut attached = false;
            let mut last_r = None;
            for _ in 0..15 {
            // Full mode first (refresh metadata keeps IddCx drivers producing
            // frames); fall back to the minimal form some drivers require.
            let mut dm = DEVMODEW {
                dmSize: size_of::<DEVMODEW>() as u16,
                dmFields: DM_POSITION
                    | DM_PELSWIDTH
                    | DM_PELSHEIGHT
                    | DM_BITSPERPEL
                    | DM_DISPLAYFREQUENCY,
                dmPelsWidth: width,
                dmPelsHeight: height,
                dmBitsPerPel: 32,
                dmDisplayFrequency: 60,
                ..Default::default()
            };
            dm.Anonymous1.Anonymous2.dmPosition = POINTL { x: far_x, y: far_y };
            let name_w = to_wide(&name);
            let r = unsafe {
                ChangeDisplaySettingsExW(
                    PCWSTR(name_w.as_ptr()),
                    Some(&dm as *const DEVMODEW),
                    None,
                    CDS_UPDATEREGISTRY,
                    None,
                )
            };
            let r = if r != windows::Win32::Graphics::Gdi::DISP_CHANGE_SUCCESSFUL {
                let mut dm2 = DEVMODEW {
                    dmSize: size_of::<DEVMODEW>() as u16,
                    dmFields: DM_POSITION | DM_PELSWIDTH | DM_PELSHEIGHT,
                    dmPelsWidth: width,
                    dmPelsHeight: height,
                    ..Default::default()
                };
                dm2.Anonymous1.Anonymous2.dmPosition = POINTL { x: far_x, y: far_y };
                unsafe {
                    ChangeDisplaySettingsExW(
                        PCWSTR(name_w.as_ptr()),
                        Some(&dm2 as *const DEVMODEW),
                        None,
                        CDS_UPDATEREGISTRY,
                        None,
                    )
                }
            } else {
                r
            };
            if r == windows::Win32::Graphics::Gdi::DISP_CHANGE_SUCCESSFUL {
                attached = true;
                break;
            }
            last_r = Some(r);
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        if !attached {
            return Err(format!("ChangeDisplaySettingsExW failed: {:?}", last_r));
        }
        }
        std::thread::sleep(std::time::Duration::from_millis(1500));
    }

    // The attach (either path) may come up with a stored database mode. Try
    // to set our mode via CDS (works on some drivers), then park the display
    // top-adjacent via CCD - position-only, since IddCx rejects resolution
    // changes on some builds, and Windows rejects non-adjacent "island"
    // positions entirely (the physical cursor can only reach a top-adjacent
    // display by pushing off the screen's top edge).
    {
        let dm = DEVMODEW {
            dmSize: size_of::<DEVMODEW>() as u16,
            dmFields: DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL | DM_DISPLAYFREQUENCY,
            dmPelsWidth: width,
            dmPelsHeight: height,
            dmBitsPerPel: 32,
            dmDisplayFrequency: 60,
            ..Default::default()
        };
        let name_w = to_wide(&name);
        let _ = unsafe {
            ChangeDisplaySettingsExW(
                PCWSTR(name_w.as_ptr()),
                Some(&dm as *const DEVMODEW),
                None,
                CDS_UPDATEREGISTRY,
                None,
            )
        };
        // Read the display's ACTUAL current mode to compute the parking spot.
        let mut cur = DEVMODEW {
            dmSize: size_of::<DEVMODEW>() as u16,
            ..Default::default()
        };
        let ok = unsafe {
            EnumDisplaySettingsW(
                PCWSTR(name_w.as_ptr()),
                windows::Win32::Graphics::Gdi::ENUM_CURRENT_SETTINGS,
                &mut cur,
            )
        };
        let (px, py) = if ok.as_bool() && cur.dmPelsHeight > 0 {
            (0, -(cur.dmPelsHeight as i32))
        } else {
            (0, -(height as i32))
        };
        let _ = ccd_set_position(px, py);
        std::thread::sleep(std::time::Duration::from_millis(800));
        return Ok((name, px, py));
    }
}

/// Detach the virtual display (zero-size mode removes it from the desktop
/// topology) — the machine returns to its original single-screen layout.
pub fn detach_display() {
    let Some((name, active)) = find_virtual_display() else {
        return;
    };
    if !active {
        return;
    }
    let mut dm = DEVMODEW {
        dmSize: size_of::<DEVMODEW>() as u16,
        dmFields: DM_POSITION | DM_PELSWIDTH | DM_PELSHEIGHT,
        dmPelsWidth: 0,
        dmPelsHeight: 0,
        ..Default::default()
    };
    dm.Anonymous1.Anonymous2.dmPosition = POINTL { x: 0, y: 0 };
    let name_w = to_wide(&name);
    unsafe {
        let _ = ChangeDisplaySettingsExW(
            PCWSTR(name_w.as_ptr()),
            Some(&dm as *const DEVMODEW),
            None,
            CDS_UPDATEREGISTRY,
            None,
        );
    }
}

/// Default parking spot for production use.
pub fn ensure_display(width: u32, height: u32) -> Result<(String, i32, i32), String> {
    ensure_display_at(width, height, 30_000, 30_000)
}

/// Dev harness: enumerate the virtual display's supported modes.
pub fn list_modes() {
    let Some((name, active)) = find_virtual_display() else {
        println!("no virtual display device");
        return;
    };
    println!("device {} active={}", name, active);
    let name_w = to_wide(&name);
    unsafe {
        // Registry (current) mode.
        let mut cur = DEVMODEW {
            dmSize: size_of::<DEVMODEW>() as u16,
            ..Default::default()
        };
        let ok = EnumDisplaySettingsW(
            PCWSTR(name_w.as_ptr()),
            ENUM_REGISTRY_SETTINGS,
            &mut cur,
        );
        println!(
            "registry mode: ok={} {}x{}@{}Hz pos=({},{})",
            ok.as_bool(),
            cur.dmPelsWidth,
            cur.dmPelsHeight,
            cur.dmDisplayFrequency,
            cur.Anonymous1.Anonymous2.dmPosition.x,
            cur.Anonymous1.Anonymous2.dmPosition.y,
        );
        // Supported modes.
        let mut count = 0;
        for i in 0..500u32 {
            let mut dm = DEVMODEW {
                dmSize: size_of::<DEVMODEW>() as u16,
                ..Default::default()
            };
            let ok = EnumDisplaySettingsW(PCWSTR(name_w.as_ptr()), windows::Win32::Graphics::Gdi::ENUM_DISPLAY_SETTINGS_MODE(i), &mut dm);
            if !ok.as_bool() {
                break;
            }
            count += 1;
            if true {
                println!(
                    "mode[{}]: {}x{} @{}Hz {}bpp",
                    i, dm.dmPelsWidth, dm.dmPelsHeight, dm.dmDisplayFrequency, dm.dmBitsPerPel
                );
            }
        }
        println!("total supported modes: {}", count);
    }
}

/// Dev harness: dump every GDI display device.
pub fn dump_displays() {
    for (name, id, active) in enum_displays() {
        println!("{} | id={} | active={}", name, id, active);
    }
}

/// Attach the virtual display via the CCD API: build a path for its target
/// and apply it (Windows persists "PC screen only"-style detached topology
/// that ChangeDisplaySettingsEx refuses to override).
pub fn ccd_attach(width: u32, height: u32, far_x: i32, far_y: i32) -> Result<(), String> {
    use windows::Win32::Devices::Display::{
        GetDisplayConfigBufferSizes, QueryDisplayConfig, SetDisplayConfig, QDC_ALL_PATHS,
        SDC_ALLOW_CHANGES, SDC_APPLY, SDC_USE_SUPPLIED_DISPLAY_CONFIG, DISPLAYCONFIG_MODE_INFO,
        DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE, DISPLAYCONFIG_PATH_INFO,
    };
    use windows::Win32::Foundation::POINTL as PT;
    const DISPLAYCONFIG_PATH_ACTIVE: u32 = 1;

    unsafe {
        let mut npaths = 0u32;
        let mut nmodes = 0u32;
        let r = GetDisplayConfigBufferSizes(QDC_ALL_PATHS, &mut npaths, &mut nmodes);
        if r.0 != 0 {
            return Err(format!("GetDisplayConfigBufferSizes: {:?}", r));
        }
        let mut paths = vec![DISPLAYCONFIG_PATH_INFO::default(); npaths as usize];
        let mut modes = vec![DISPLAYCONFIG_MODE_INFO::default(); nmodes as usize];
        let mut npaths2 = npaths;
        let mut nmodes2 = nmodes;
        let r = QueryDisplayConfig(
            QDC_ALL_PATHS,
            &mut npaths2,
            paths.as_mut_ptr(),
            &mut nmodes2,
            modes.as_mut_ptr(),
            None,
        );
        if r.0 != 0 {
            return Err(format!("QueryDisplayConfig: {:?}", r));
        }
        paths.truncate(npaths2 as usize);
        modes.truncate(nmodes2 as usize);

        // The VDD path = the one whose adapter differs from the currently
        // active display's adapter.
        let active_adapter = paths
            .iter()
            .find(|p| p.flags & DISPLAYCONFIG_PATH_ACTIVE != 0)
            .map(|p| p.targetInfo.adapterId);
        let Some(vdd_idx) = paths.iter().position(|p| {
            p.flags & DISPLAYCONFIG_PATH_ACTIVE == 0
                && active_adapter.map_or(true, |a| {
                    a.LowPart != p.targetInfo.adapterId.LowPart
                        || a.HighPart != p.targetInfo.adapterId.HighPart
                })
        }) else {
            return Err("ccd: no inactive VDD path found".to_string());
        };
        paths[vdd_idx].flags |= DISPLAYCONFIG_PATH_ACTIVE;

        // Give its source mode our resolution and off-screen position.
        let vdd_adapter = paths[vdd_idx].targetInfo.adapterId;
        for m in modes.iter_mut() {
            if m.infoType != DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE {
                continue;
            }
            if m.adapterId.LowPart != vdd_adapter.LowPart
                || m.adapterId.HighPart != vdd_adapter.HighPart
            {
                continue;
            }
            let src = &mut m.Anonymous.sourceMode;
            src.position = PT { x: far_x, y: far_y };
            src.width = width;
            src.height = height;
        }
        let r = SetDisplayConfig(
            Some(&paths),
            Some(&modes),
            SDC_APPLY | SDC_USE_SUPPLIED_DISPLAY_CONFIG | SDC_ALLOW_CHANGES,
        );
        if r != 0 {
            return Err(format!("SetDisplayConfig: {}", r));
        }
        Ok(())
    }
}

/// Dev harness: dump the CCD path database.
pub fn dump_paths() {
    use windows::Win32::Devices::Display::{
        GetDisplayConfigBufferSizes, QueryDisplayConfig, QDC_DATABASE_CURRENT, DISPLAYCONFIG_MODE_INFO,
        DISPLAYCONFIG_PATH_INFO,
    };
    unsafe {
        let mut npaths = 0u32;
        let mut nmodes = 0u32;
        let r = GetDisplayConfigBufferSizes(QDC_DATABASE_CURRENT, &mut npaths, &mut nmodes);
        println!("buffer sizes: {:?} paths={} modes={}", r, npaths, nmodes);
        let mut paths = vec![DISPLAYCONFIG_PATH_INFO::default(); npaths as usize];
        let mut modes = vec![DISPLAYCONFIG_MODE_INFO::default(); nmodes as usize];
        let mut npaths2 = npaths;
        let mut nmodes2 = nmodes;
        let mut topo: windows::Win32::Devices::Display::DISPLAYCONFIG_TOPOLOGY_ID = Default::default();
        let r = QueryDisplayConfig(
            QDC_DATABASE_CURRENT,
            &mut npaths2,
            paths.as_mut_ptr(),
            &mut nmodes2,
            modes.as_mut_ptr(),
            Some(&mut topo),
        );
        println!("query: {:?} paths={} modes={}", r, npaths2, nmodes2);
        paths.truncate(npaths2 as usize);
        for (i, p) in paths.iter().enumerate() {
            println!(
                "path[{}]: flags={} targetAvail={} adapterLUID=({}, {}) targetId={}",
                i,
                p.flags,
                p.targetInfo.targetAvailable.as_bool(),
                p.targetInfo.adapterId.LowPart,
                p.targetInfo.adapterId.HighPart,
                p.targetInfo.id,
            );
        }
        let _ = modes;
    }
}

/// Reposition/resize the ACTIVE virtual display via CCD (works where
/// ChangeDisplaySettingsEx fails on IddCx devices).
pub fn ccd_set_mode(width: u32, height: u32, far_x: i32, far_y: i32) -> Result<(), String> {
    use windows::Win32::Devices::Display::{
        GetDisplayConfigBufferSizes, QueryDisplayConfig, SetDisplayConfig, QDC_ONLY_ACTIVE_PATHS,
        SDC_APPLY, SDC_USE_SUPPLIED_DISPLAY_CONFIG, DISPLAYCONFIG_MODE_INFO,
        DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE, DISPLAYCONFIG_PATH_INFO,
    };
    use windows::Win32::Foundation::POINTL as PT;
    const DISPLAYCONFIG_PATH_ACTIVE: u32 = 1;

    unsafe {
        let mut npaths = 0u32;
        let mut nmodes = 0u32;
        let r = GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, &mut npaths, &mut nmodes);
        if r.0 != 0 {
            return Err(format!("GetDisplayConfigBufferSizes: {:?}", r));
        }
        let mut paths = vec![DISPLAYCONFIG_PATH_INFO::default(); npaths as usize];
        let mut modes = vec![DISPLAYCONFIG_MODE_INFO::default(); nmodes as usize];
        let mut npaths2 = npaths;
        let mut nmodes2 = nmodes;
        let r = QueryDisplayConfig(
            QDC_ONLY_ACTIVE_PATHS,
            &mut npaths2,
            paths.as_mut_ptr(),
            &mut nmodes2,
            modes.as_mut_ptr(),
            None,
        );
        if r.0 != 0 {
            return Err(format!("QueryDisplayConfig: {:?}", r));
        }
        paths.truncate(npaths2 as usize);
        modes.truncate(nmodes2 as usize);

        // Identify the VDD path as the active path whose source is NOT at
        // the primary's (0,0) - robust across adapter LUID changes and
        // cross-adapter rendering on single-real-monitor machines.
        let mut target_idx = None;
        for (i2, p) in paths.iter().enumerate() {
            if p.flags & DISPLAYCONFIG_PATH_ACTIVE == 0 {
                continue;
            }
            // find this path's source mode position
            let mut pos = (0i32, 0i32);
            for m in modes.iter() {
                if m.infoType != DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE {
                    continue;
                }
                if m.adapterId.LowPart == p.sourceInfo.adapterId.LowPart {
                    pos = (m.Anonymous.sourceMode.position.x, m.Anonymous.sourceMode.position.y);
                    break;
                }
            }
            if pos.0 != 0 || pos.1 != 0 {
                target_idx = Some(i2);
                break;
            }
        }
        let Some(ti) = target_idx else {
            return Err("ccd_set_mode: virtual path not found".to_string());
        };
        let adapter = paths[ti].targetInfo.adapterId;
        for m in modes.iter_mut() {
            if m.infoType != DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE {
                continue;
            }
            if m.adapterId.LowPart != adapter.LowPart
            {
                continue;
            }
            let src = &mut m.Anonymous.sourceMode;
            src.position = PT { x: far_x, y: far_y };
            src.width = width;
            src.height = height;
        }
        let r = SetDisplayConfig(
            Some(&paths),
            Some(&modes),
            SDC_APPLY | SDC_USE_SUPPLIED_DISPLAY_CONFIG,
        );
        if r != 0 {
            return Err(format!("SetDisplayConfig: {}", r));
        }
        Ok(())
    }
}

/// LUID of the adapter owning the virtual display (via DXGI).
pub fn vdd_adapter_luid() -> Option<windows::Win32::Foundation::LUID> {
    use windows::Win32::Graphics::Dxgi::{CreateDXGIFactory1, IDXGIFactory1};
    let (name, _) = find_virtual_display()?;
    unsafe {
        let factory: IDXGIFactory1 = CreateDXGIFactory1().ok()?;
        for ai in 0..16 {
            let Ok(adapter) = factory.EnumAdapters1(ai) else { break };
            for oi in 0..16 {
                let Ok(output) = adapter.EnumOutputs(oi) else { break };
                let Ok(desc) = output.GetDesc() else { continue };
                let len = desc
                    .DeviceName
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(desc.DeviceName.len());
                let out_name = String::from_utf16_lossy(&desc.DeviceName[..len]);
                if out_name == name {
                    let adesc = adapter.GetDesc1().ok()?;
                    return Some(adesc.AdapterLuid);
                }
            }
        }
    }
    None
}

/// Reposition the ACTIVE virtual display (position only — resolution changes
/// are rejected by IddCx devices on some builds, positions are accepted).
/// The target is the active path whose source is NOT at the primary's (0,0).
pub fn ccd_set_position(x: i32, y: i32) -> Result<(), String> {
    use windows::Win32::Devices::Display::{
        GetDisplayConfigBufferSizes, QueryDisplayConfig, SetDisplayConfig, QDC_ONLY_ACTIVE_PATHS,
        SDC_APPLY, SDC_USE_SUPPLIED_DISPLAY_CONFIG, DISPLAYCONFIG_MODE_INFO,
        DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE, DISPLAYCONFIG_PATH_INFO,
    };
    use windows::Win32::Foundation::POINTL as PT;
    const DISPLAYCONFIG_PATH_ACTIVE: u32 = 1;

    unsafe {
        let mut npaths = 0u32;
        let mut nmodes = 0u32;
        let r = GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, &mut npaths, &mut nmodes);
        if r.0 != 0 {
            return Err(format!("GetDisplayConfigBufferSizes: {:?}", r));
        }
        let mut paths = vec![DISPLAYCONFIG_PATH_INFO::default(); npaths as usize];
        let mut modes = vec![DISPLAYCONFIG_MODE_INFO::default(); nmodes as usize];
        let mut npaths2 = npaths;
        let mut nmodes2 = nmodes;
        let r = QueryDisplayConfig(
            QDC_ONLY_ACTIVE_PATHS,
            &mut npaths2,
            paths.as_mut_ptr(),
            &mut nmodes2,
            modes.as_mut_ptr(),
            None,
        );
        if r.0 != 0 {
            return Err(format!("QueryDisplayConfig: {:?}", r));
        }
        paths.truncate(npaths2 as usize);
        modes.truncate(nmodes2 as usize);

        let mut edited = false;
        for m in modes.iter_mut() {
            if m.infoType != DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE {
                continue;
            }
            let pos = &mut m.Anonymous.sourceMode.position;
            if pos.x == 0 && pos.y == 0 {
                continue; // the primary
            }
            *pos = PT { x, y };
            edited = true;
        }
        if !edited {
            return Err("ccd_set_position: virtual path not found".to_string());
        }
        let r = SetDisplayConfig(
            Some(&paths),
            Some(&modes),
            SDC_APPLY | SDC_USE_SUPPLIED_DISPLAY_CONFIG,
        );
        if r != 0 {
            return Err(format!("SetDisplayConfig: {}", r));
        }
        Ok(())
    }
}
