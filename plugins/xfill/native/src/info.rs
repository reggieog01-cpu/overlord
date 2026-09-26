//! Info.json summary manifest — drives the xfill UI table.
//! Field names match the competition zip format (PascalCase).

use serde::Serialize;

#[derive(Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Info {
    pub created_at: String,
    pub session_id: String,
    pub username: String,
    #[serde(rename = "HWID")]
    pub hwid: String,
    pub group: String,
    pub ip_address: String,
    pub country: String,
    pub operating_system: String,
    pub os_version: String,
    pub cpu_name: String,
    pub gpu_name: String,
    pub ram_size: String,
    pub screen_size: String,
    pub anti_virus: String,
    pub payload_path: String,
    pub first_time: bool,
    pub version: String,
    pub note: String,
    pub folder_path: String,
    pub passwords_count: usize,
    pub cookies_count: usize,
    pub history_count: usize,
    pub autofill_count: usize,
    pub credit_cards_count: usize,
    pub browser_extensions_count: usize,
    pub browsers: Vec<String>,
    pub browser_extensions: Vec<String>,
    pub desktop_wallets: Vec<String>,
    pub apps: Vec<String>,
    pub clipboard: String,
}

impl Info {
    pub fn new() -> Self {
        Self {
            group: "Default".into(),
            version: "1.0.0".into(),
            first_time: true,
            anti_virus: "unknown".into(),
            ..Default::default()
        }
    }

    /// Record a found browser, deduplicated, preserving discovery order.
    pub fn add_browser(&mut self, name: &str) {
        push_unique(&mut self.browsers, name);
    }

    pub fn add_extension(&mut self, name: &str) {
        push_unique(&mut self.browser_extensions, name);
        self.browser_extensions_count = self.browser_extensions.len();
    }

    pub fn add_wallet(&mut self, name: &str) {
        push_unique(&mut self.desktop_wallets, name);
    }

    pub fn add_app(&mut self, name: &str) {
        push_unique(&mut self.apps, name);
    }
}

fn push_unique(list: &mut Vec<String>, name: &str) {
    if !list.iter().any(|e| e == name) {
        list.push(name.to_string());
    }
}
