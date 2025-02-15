use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppConfig {
    pub(crate) route_map: HashMap<String, String>
}

impl Default for AppConfig {
    fn default () -> AppConfig {
        AppConfig {route_map: HashMap::new()}
    }
}