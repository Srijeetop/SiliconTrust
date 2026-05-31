/// collect.rs — Windows hardware identifier collector
///
/// All 9 sources read directly via Win32 APIs, the registry, and CPUID.
/// No PowerShell, no WMI subprocess, no external tools.

use crate::fingerprint::HardwareFingerprint;
use windows::Win32::Foundation::BOOLEAN;

// ── 1. CPUID ─────────────────────────────────────────────────────────────────

fn collect_cpuid() -> Option<String> {
    use raw_cpuid::CpuId;

    let cpuid = CpuId::new();
    let mut parts = Vec::new();

    if let Some(v) = cpuid.get_vendor_info() {
        parts.push(v.as_str().to_string());
    }

    if let Some(fi) = cpuid.get_feature_info() {
        parts.push(format!(
            "fam{:02X}mod{:02X}step{:02X}",
            fi.family_id(),
            fi.model_id(),
            fi.stepping_id()
        ));
    }

    if let Some(b) = cpuid.get_processor_brand_string() {
        parts.push(b.as_str().trim().replace(' ', "_").to_string());
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("|"))
    }
}

// ── 2. SMBIOS UUID ───────────────────────────────────────────────────────────

fn collect_smbios_uuid() -> Option<String> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut parts = Vec::new();

    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Microsoft\Cryptography") {
        if let Ok(guid) = key.get_value::<String, _>("MachineGuid") {
            parts.push(guid);
        }
    }

    if let Ok(key) = hklm.open_subkey(r"HARDWARE\DESCRIPTION\System\BIOS") {
        for field in &[
            "BaseBoardProduct",
            "BaseBoardManufacturer",
            "BIOSVersion",
            "BIOSReleaseDate",
            "SystemProductName",
        ] {
            if let Ok(v) = key.get_value::<String, _>(field) {
                parts.push(v);
            }
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("|"))
    }
}

// ── 3. NIC MAC address ───────────────────────────────────────────────────────

fn collect_nic_mac() -> Option<String> {
    use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses,
        IP_ADAPTER_ADDRESSES_LH,
        GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
    const IF_TYPE_IEEE80211: u32 = 71;

    let flags =
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

    let mut buf_len: u32 = 16 * 1024;
    let mut buf: Vec<u8> = vec![0u8; buf_len as usize];

    loop {
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut buf_len,
            )
        };

        if ret == ERROR_BUFFER_OVERFLOW.0 {
            buf.resize(buf_len as usize, 0);
            continue;
        }

        if ret != 0 {
            return None;
        }

        break;
    }

    let mut adapter =
        unsafe { &*(buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH) };

    loop {
        let if_type = adapter.IfType;

        if (if_type == IF_TYPE_ETHERNET_CSMACD
            || if_type == IF_TYPE_IEEE80211)
            && adapter.PhysicalAddressLength == 6
        {
            let mac = &adapter.PhysicalAddress[..6];

            if mac.iter().any(|&b| b != 0) {
                return Some(format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5]
                ));
            }
        }

        if adapter.Next.is_null() {
            break;
        }

        adapter = unsafe { &*adapter.Next };
    }

    None
}

// ── 4. Drive serial number ───────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct STORAGE_PROPERTY_QUERY {
    property_id: u32,
    query_type: u32,
    additional: [u8; 1],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct STORAGE_DEVICE_DESCRIPTOR {
    version: u32,
    size: u32,
    device_type: u8,
    device_type_modifier: u8,
    removable_media: BOOLEAN,
    command_queueing: BOOLEAN,
    vendor_id_offset: u32,
    product_id_offset: u32,
    product_revision_offset: u32,
    serial_number_offset: u32,
    bus_type: u32,
    raw_properties_length: u32,
    raw_device_properties: [u8; 1],
}

const STORAGE_DEVICE_PROPERTY: u32 = 0;
const PROPERTY_STANDARD_QUERY: u32 = 0;

fn collect_ssd_serial() -> Option<String> {
    use std::ffi::{c_void, CStr};
    use std::mem::size_of;

    use windows::core::PCWSTR;

    use windows::Win32::Foundation::{
        CloseHandle,
        HANDLE,
    };

    use windows::Win32::Storage::FileSystem::{
        CreateFileW,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };

    use windows::Win32::System::IO::DeviceIoControl;

    use windows::Win32::System::Ioctl::{
        IOCTL_STORAGE_QUERY_PROPERTY,
    };

    unsafe {
        let path: Vec<u16> =
            "\\\\.\\PhysicalDrive0"
                .encode_utf16()
                .chain(Some(0))
                .collect();

        let handle = CreateFileW(
            PCWSTR(path.as_ptr()),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(std::ptr::null_mut()),
        );

        let handle = handle.ok()?;

        let query = STORAGE_PROPERTY_QUERY {
            property_id: STORAGE_DEVICE_PROPERTY,
            query_type: PROPERTY_STANDARD_QUERY,
            additional: [0],
        };

        let mut outbuf = vec![0u8; 1024];

        let mut returned = 0u32;

        let ok = DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some(&query as *const _ as *const c_void),
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            Some(outbuf.as_mut_ptr() as *mut c_void),
            outbuf.len() as u32,
            Some(&mut returned),
            None,
        );

        let _ = CloseHandle(handle);

        if ok.is_err() {
            return None;
        }

        let desc =
            outbuf.as_ptr()
                as *const STORAGE_DEVICE_DESCRIPTOR;

        let offset =
            (*desc).serial_number_offset;

        if offset == 0 {
            return None;
        }

        let ptr =
            outbuf.as_ptr().add(offset as usize);

        let serial =
            CStr::from_ptr(ptr as *const i8)
                .to_string_lossy()
                .trim()
                .to_string();

        if serial.is_empty() {
            None
        } else {
            Some(serial)
        }
    }
}

// ── 5. TPM identity ──────────────────────────────────────────────────────────

fn collect_tpm_ek() -> Option<String> {
    use std::process::Command;

    let ps_command = r#"
$ek = Get-TpmEndorsementKeyInfo
[BitConverter]::ToString($ek.PublicKey.RawData).Replace("-", "")
"#;

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            ps_command,
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let ek_hex =
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_string();

    if ek_hex.is_empty() {
        None
    } else {
        Some(ek_hex)
    }
}

// ── 6. GPU device ID ─────────────────────────────────────────────────────────

fn collect_gpu_device_id() -> Option<String> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    let path =
        r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";

    let class = hklm.open_subkey(path).ok()?;

    let mut ids = Vec::new();

    for subkey_name in class.enum_keys().filter_map(|k| k.ok()) {
        if !subkey_name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        if let Ok(sub) = class.open_subkey(&subkey_name) {
            let mut parts = Vec::new();

            if let Ok(v) =
    	    	sub.get_value::<String, _>("MatchingDeviceId")
            {
    		parts.push(v);
             }

            if !parts.is_empty() {
                ids.push(parts.join(":"));
            }
        }
    }

    if ids.is_empty() {
        None
    } else {
        Some(ids.join("|"))
    }
}

// ── 7. DIMM SPD ──────────────────────────────────────────────────────────────

fn collect_dimm_spd() -> Option<String> {
    use windows::Win32::System::SystemInformation::{
        FIRMWARE_TABLE_PROVIDER,
        GetSystemFirmwareTable,
    };

    let sig = FIRMWARE_TABLE_PROVIDER(0x52534D42u32);

    let needed = unsafe { GetSystemFirmwareTable(sig, 0, None) };

    if needed == 0 {
        return dimm_from_registry();
    }

    let mut buf = vec![0u8; needed as usize];

    let got = unsafe {
        GetSystemFirmwareTable(sig, 0, Some(&mut buf))
    };

    if got == 0 {
        return dimm_from_registry();
    }

    if buf.len() < 8 {
        return dimm_from_registry();
    }

    let smbios = &buf[8..];

    parse_smbios_type17(smbios).or_else(dimm_from_registry)
}

fn parse_smbios_type17(smbios: &[u8]) -> Option<String> {
    let mut results = Vec::new();
    let mut i = 0;

    while i + 4 < smbios.len() {
        let stype = smbios[i];
        let length = smbios[i + 1] as usize;

        if length < 4 || i + length > smbios.len() {
            break;
        }

        let str_area_start = i + length;
        let mut str_area_end = str_area_start;

        while str_area_end + 1 < smbios.len() {
            if smbios[str_area_end] == 0
                && smbios[str_area_end + 1] == 0
            {
                str_area_end += 2;
                break;
            }

            str_area_end += 1;
        }

        if stype == 17 && length >= 28 {
            let strings = extract_smbios_strings(
                &smbios[str_area_start..str_area_end],
            );

            let get = |idx: usize| -> Option<String> {
                if idx == 0 || idx > strings.len() {
                    None
                } else {
                    Some(strings[idx - 1].clone())
                }
            };

            let mfr = get(smbios[i + 23] as usize);
            let ser = get(smbios[i + 24] as usize);
            let part = get(smbios[i + 26] as usize);

            let size_mb = u16::from_le_bytes([
    		smbios[i + 0x0C],
    		smbios[i + 0x0D],
	    ]);

	    let mut entry: Vec<String> =
    		[mfr, part, ser]
        		.into_iter()
        		.flatten()
        		.collect();

	    if size_mb != 0 {
    		entry.push(format!("{}MB", size_mb));
	    }

            if !entry.is_empty() {
                results.push(entry.join(":"));
            }
        }

        i = str_area_end;
    }

    if results.is_empty() {
        None
    } else {
        Some(results.join("|"))
    }
}

fn extract_smbios_strings(area: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current: Vec<u8> = Vec::new();

    for &b in area {
        if b == 0 {
            if current.is_empty() {
                break;
            }

            strings.push(
                String::from_utf8_lossy(&current).into_owned(),
            );

            current.clear();
        } else {
            current.push(b);
        }
    }

    strings
}

fn dimm_from_registry() -> Option<String> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    if let Ok(key) = hklm.open_subkey(
        r"HARDWARE\DESCRIPTION\System\MultifunctionAdapter",
    ) {
        for sub in key.enum_keys().filter_map(|k| k.ok()) {
            if let Ok(entry) = key.open_subkey(&sub) {
                if let Ok(id) =
                    entry.get_value::<String, _>("Identifier")
                {
                    if id.to_lowercase().contains("mem") {
                        return Some(id);
                    }
                }
            }
        }
    }

    None
}

// ── 8. Cache topology ────────────────────────────────────────────────────────

fn collect_cache_topology() -> Option<String> {
    use raw_cpuid::CpuId;

    let cpuid = CpuId::new();
    let mut entries = Vec::new();

    if let Some(cparams) = cpuid.get_cache_parameters() {
        for cache in cparams {
            use raw_cpuid::CacheType;

            let t = match cache.cache_type() {
                CacheType::Data => "D",
                CacheType::Instruction => "I",
                CacheType::Unified => "U",
                _ => continue,
            };

            let size_kb = (
                cache.associativity()
                    * cache.physical_line_partitions()
                    * cache.coherency_line_size()
                    * cache.sets()
            ) / 1024;

            entries.push(format!(
                "L{}{t}:{}KB:{}way",
                cache.level(),
                size_kb,
                cache.associativity()
            ));
        }
    }

    if entries.is_empty() {
        if let Some(v) = cache_from_winapi() {
            return Some(v);
        }
    }

    entries.sort();

    if entries.is_empty() {
        None
    } else {
        Some(entries.join("|"))
    }
}

fn cache_from_winapi() -> Option<String> {
    use windows::Win32::System::SystemInformation::{
        GetLogicalProcessorInformation,
        LOGICAL_PROCESSOR_RELATIONSHIP,
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION,
    };

    const RELATION_CACHE: LOGICAL_PROCESSOR_RELATIONSHIP =
        LOGICAL_PROCESSOR_RELATIONSHIP(3);

    let mut len: u32 = 0;

    unsafe {
        GetLogicalProcessorInformation(None, &mut len)
    };

    if len == 0 {
        return None;
    }

    let count = len as usize
        / std::mem::size_of::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION>();

    let mut buf: Vec<SYSTEM_LOGICAL_PROCESSOR_INFORMATION> =
        vec![unsafe { std::mem::zeroed() }; count];

    let ok = unsafe {
        GetLogicalProcessorInformation(
            Some(buf.as_mut_ptr()),
            &mut len,
        )
    };

    if ok.is_err() {
        return None;
    }

    let mut entries = Vec::new();

    for info in &buf {
        if info.Relationship == RELATION_CACHE {
            let cache = unsafe { &info.Anonymous.Cache };

            entries.push(format!(
                "L{}:{}KB",
                cache.Level,
                cache.Size / 1024
            ));
        }
    }

    entries.sort();

    if entries.is_empty() {
        None
    } else {
        Some(entries.join("|"))
    }
}

// ── 9. PCIe topology ─────────────────────────────────────────────────────────

fn collect_pcie_topology() -> Option<String> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    let pci = hklm
        .open_subkey(r"SYSTEM\CurrentControlSet\Enum\PCI")
        .ok()?;

    let mut devices = Vec::new();

    for device in pci.enum_keys().filter_map(|k| k.ok()) {
        let clean = device
            .split('&')
            .filter(|p| {
                p.starts_with("VEN_") || p.starts_with("DEV_")
            })
            .collect::<Vec<_>>()
            .join(":");

        if !clean.is_empty() {
            devices.push(clean);
        }
    }

    if devices.is_empty() {
        return None;
    }

    devices.sort();
    devices.dedup();

    Some(devices.join("|"))
}

// ── Public entry point ───────────────────────────────────────────────────────

pub fn collect_fingerprint(
    verbose: bool,
) -> HardwareFingerprint {
    macro_rules! collect {
        ($label:expr, $value:expr) => {{
            let val = $value;

            if verbose {
                match &val {
                    Some(v) => {
                        let preview =
                            &v[..v.len().min(60)];

                        eprintln!(
                            "  ✓  {:<16} = {}...",
                            $label,
                            preview
                        );
                    }

                    None => {
                        eprintln!(
                            "  ✗  {:<16} (not available)",
                            $label
                        );
                    }
                }
            }

            val
        }};
    }

    if verbose {
        eprintln!(
            "[hec] Collecting hardware fingerprint..."
        );
    }

    let fp = HardwareFingerprint {
        cpuid: collect!("cpuid", collect_cpuid()),

        smbios_uuid: collect!(
            "smbios_uuid",
            collect_smbios_uuid()
        ),

        nic_mac: collect!(
            "nic_mac",
            collect_nic_mac()
        ),

        ssd_serial: collect!(
            "ssd_serial",
            collect_ssd_serial()
        ),

        tpm_ek: collect!(
            "tpm_ek",
            collect_tpm_ek()
        ),

        gpu_device_id: collect!(
            "gpu_device_id",
            collect_gpu_device_id()
        ),

        dimm_spd: collect!(
            "dimm_spd",
            collect_dimm_spd()
        ),

        cache_topology: collect!(
            "cache_topology",
            collect_cache_topology()
        ),

        pcie_topology: collect!(
            "pcie_topology",
            collect_pcie_topology()
        ),
    };

    if verbose {
        let n = fp.present_sources().len();

        if n >= crate::fingerprint::THRESHOLD {
            eprintln!(
                "[hec] {}/9 sources — threshold met ({} required)",
                n,
                crate::fingerprint::THRESHOLD
            );
        } else {
            eprintln!(
                "[hec] WARNING: only {}/9 sources — need {} to encrypt/decrypt",
                n,
                crate::fingerprint::THRESHOLD
            );
        }
    }

    fp
}