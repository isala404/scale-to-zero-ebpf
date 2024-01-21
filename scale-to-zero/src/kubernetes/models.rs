use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

// This contains a mapper of service IPs to availablity of it's backends
// If pods are available, the value is true, if not, false
pub static WATCHED_SERVICES: Lazy<Arc<Mutex<HashMap<String, ServiceData>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

// This is used to keep track of when a service was last scaled up
pub static LAST_CALLED: Lazy<Mutex<HashMap<String, SystemTime>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Eq, Hash, PartialEq)]
pub struct WorkloadReference {
    pub kind: String,
    pub name: String,
    pub namespace: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServiceData {
    pub scale_down_time: i64,
    pub last_packet_time: i64,
    pub kind: String,
    pub name: String,
    pub namespace: String,
    pub backend_available: bool,
}
