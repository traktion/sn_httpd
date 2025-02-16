use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use globset::Glob;
use log::{debug, info};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppConfig {
    route_map: HashMap<String, String>
}

impl AppConfig {

    pub fn default() -> Self {
        Self {
            route_map: HashMap::new(),
        }
    }
    
    pub fn resolve_route(&self, relative_path: String, archive_file_name: String) -> (String, bool) {
        for (key, value) in self.route_map.clone() {
            let glob = Glob::new(key.as_str()).unwrap().compile_matcher();
            debug!("route mapper comparing path [{}] with glob [{}]", relative_path, key);
            if glob.is_match(&relative_path) {
                info!("route mapper resolved path [{}] to [{}] with glob [{}]", relative_path, key, value);
                return (value, true);
            }
        };
        (archive_file_name, false)
    }
}