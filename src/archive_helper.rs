use std::path::PathBuf;
use actix_http::header::HeaderMap;
use autonomi::data::DataAddr;
use autonomi::files::PublicArchive;
use chrono::DateTime;
use color_eyre::{Report, Result};
use log::{debug, info};
use xor_name::XorName;

#[derive(Clone)]
pub struct ArchiveHelper {
    archive: PublicArchive
}

#[derive(Clone)]
pub struct ArchiveInfo {
    pub path_string: String,
    pub resolved_xor_addr: XorName,
    pub is_listing: bool,
    pub has_moved_permanently: bool,
    pub is_not_found: bool
}

impl ArchiveInfo {
    pub fn new(path_string: String, resolved_xor_addr: XorName, is_listing: bool, has_moved_permanently: bool, is_not_found: bool) -> ArchiveInfo {
        ArchiveInfo { path_string, resolved_xor_addr, is_listing, has_moved_permanently, is_not_found }
    }
}

impl ArchiveHelper {
    pub fn new(public: PublicArchive) -> ArchiveHelper {
        ArchiveHelper { archive: public }
    }
    
    pub fn list_files(&self, header_map: &HeaderMap) -> String{
        if header_map.contains_key("Accept")
            && header_map.get("Accept").unwrap().to_str().unwrap().to_string().contains( "json") {
            self.list_files_json()
        } else {
            self.list_files_html()
        }
    }

    fn list_files_html(&self) -> String {
        let mut output = "<html><body><ul>".to_string();

        // todo: Replace with contains() once keys are a more useful shape
        for key in self.archive.map().keys() {
            let filepath = key.to_str().unwrap().to_string().trim_start_matches("./").to_string();
            output.push_str(&format!("<li><a href=\"{}\">{}</a></li>\n", filepath, filepath));
        }
        output.push_str("</ul></body></html>");
        output
    }

    fn list_files_json(&self) -> String {
        let mut output = "[\n".to_string();

        let mut i = 1;
        let count = self.archive.map().keys().len();
        for key in self.archive.map().keys() {
            let (_, metadata) = self.archive.map().get(key).unwrap();
            let mtime_datetime = DateTime::from_timestamp_millis(metadata.modified as i64 * 1000).unwrap();
            let mtime_iso = mtime_datetime.format("%+");
            let filepath = key.to_str().unwrap().to_string().trim_start_matches("./").to_string();
            output.push_str("{");
            output.push_str(&format!("\"name\": \"{}\", \"type\": \"file\", \"mtime\": \"{}\", \"size\": \"{}\"", filepath, mtime_iso, metadata.size));
            output.push_str("}");
            if i < count {
                output.push_str(",");
            }
            output.push_str("\n");
            i+=1;
        }
        output.push_str("]");
        output
    }

    pub fn resolve_data_addr(&self, path_parts: Vec<String>) -> Result<DataAddr> {
        self.archive.iter().for_each(|(path_buf, data_addr, _)| debug!("archive entry: [{}] at [{:x}]", path_buf.display(), data_addr));

        // todo: Replace with contains() once keys are a more useful shape
        let path_parts_string = path_parts[1..].join("/");
        for key in self.archive.map().keys() {
            if key.to_str().unwrap().to_string().trim_start_matches("./").ends_with(path_parts_string.as_str()) {
                let (data_addr, _) = self.archive.map().get(key).unwrap();
                return Ok(data_addr.clone())
            }
        }
        Err(Report::msg(format!("Failed to find item [{}] in archive", path_parts_string)))

        /*if archive.map().contains_key(path_buf) {
            let (data_addr, metadata) = archive
                .map()
                .get(path_buf)
                .expect(format!("Failed to retrieve [{}] from archive", path_buf.clone().display()).as_str());
            Ok(data_addr.clone())
        } else {
            Err(Report::msg(format!("Failed to find item [{}] in archive", path_buf.clone().display())))
        }*/
    }

    pub fn get_index(&self, request_path: String, resolved_filename_string: String) -> (String, XorName) {
        // hack to return index.html when present in directory root
        for key in self.archive.map().keys() {
            if key.ends_with(resolved_filename_string.to_string()) {
                let path_string = request_path + key.to_str().unwrap();
                let data_addr = self.archive.map().get(key).unwrap().0;
                return (path_string, data_addr)
            }
        }
        (String::new(), XorName::default())
    }

    pub fn resolve_archive_info(&self, path_parts: Vec<String>, request_path: &str, resolved_relative_path_route: String, has_route_map: bool) -> ArchiveInfo {
        if self.has_moved_permanently(request_path, &resolved_relative_path_route) {
            debug!("has moved permanently");
            ArchiveInfo::new(resolved_relative_path_route, DataAddr::default(), true, true, false)
        } else if has_route_map {
            // retrieve route map index
            debug!("retrieve route map index");
            let (resolved_relative_path_route, resolved_xor_addr) = self.get_index(request_path.to_string(), resolved_relative_path_route);
            ArchiveInfo::new(resolved_relative_path_route, resolved_xor_addr, false, false, false)
        } else if !resolved_relative_path_route.is_empty() {
            // retrieve path and data address
            debug!("retrieve path and data address");
            match self.resolve_data_addr(path_parts.clone()) {
                Ok(resolved_xor_addr) => {
                    let path_buf = &PathBuf::from(resolved_relative_path_route.clone());
                    info!("Resolved path [{}], path_buf [{}] to xor address [{}]", resolved_relative_path_route, path_buf.display(), format!("{:x}", resolved_xor_addr));
                    ArchiveInfo::new(resolved_relative_path_route, resolved_xor_addr, false, false, false)
                }
                Err(_err) => {
                    ArchiveInfo::new(resolved_relative_path_route, DataAddr::default(), false, false, true)
                }
            }
        } else {
            // retrieve file listing
            info!("retrieve file listing");
            ArchiveInfo::new(resolved_relative_path_route, DataAddr::default(), true, false, false)
        }
    }

    fn has_moved_permanently(&self, request_path: &str, resolved_relative_path_route: &String) -> bool {
        resolved_relative_path_route.is_empty() && request_path.to_string().chars().last() != Some('/')
    }
}