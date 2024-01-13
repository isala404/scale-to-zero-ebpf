use std::collections::{HashMap, BTreeMap};

use futures::{TryStreamExt, StreamExt, stream};
use k8s_openapi::api::core::v1::{Service, Pod};
use kube::{
    api::{Api, ListParams},
    runtime::{watcher, WatchStreamExt},
    Client, ResourceExt,
};
use log::info;
use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;

// Define the global variable
pub static SCALABLE_PODS: Lazy<Arc<Mutex<HashMap<String, String>>>> = Lazy::new(|| {
    Arc::new(Mutex::new(HashMap::new()))
});

pub async fn kube_event_watcher() -> anyhow::Result<()> {
    let mut pod_labels: HashMap<BTreeMap<String, String>, String> = HashMap::new();

    let client = Client::try_default().await?;

    let services: Api<Service> = Api::default_namespaced(client.clone());
    let pods: Api<Pod> = Api::default_namespaced(client.clone());


    let pod_watcher = watcher(pods.clone(), watcher::Config::default());
    let svc_watcher = watcher(services, watcher::Config::default());

    // select on applied events from all watchers
    let mut combo_stream = stream::select_all(vec![
        pod_watcher.applied_objects().map_ok(Watched::Pod).boxed(),
        svc_watcher.applied_objects().map_ok(Watched::Service).boxed(),
    ]);
    // SelectAll Stream elements must have the same Item, so all packed in this:
    #[allow(clippy::large_enum_variant)]
    enum Watched {
        Pod(Pod),
        Service(Service),
    }
    while let Some(o) = combo_stream.try_next().await? {
        match o {
            Watched::Pod(p) => {
                let mut labels = p.labels().clone();
                labels.remove("pod-template-hash");

                if !p.clone().status.unwrap().phase.unwrap().eq("Running") {
                    continue;
                }

                if pod_labels.contains_key(&labels) {
                    let ip = pod_labels.get(&labels).unwrap();
                    let mut scalable_pods = SCALABLE_PODS.lock().unwrap();
                    scalable_pods.remove(ip);
                    pod_labels.remove(&labels);
                    info!("Pod {} has been created, removing from scalable_pods", p.name_any());
                }
            },
            Watched::Service(s) => {
                if s.annotations().contains_key("isala.me/scale-to-zero-idle-timeout") {
                    let spec = s.spec.as_ref().unwrap().clone();
                    let selectors = spec.selector.as_ref().unwrap().clone();
                    let selector_string = pod_labels_to_string(selectors.clone());


                    for ip in spec.cluster_ips.unwrap() {
                        let lp = ListParams::default().labels(&selector_string.clone());
                        let pod_count = pods.list(&lp).await?.items.len();
                        if pod_count == 0 {
                            let mut scalable_pods = SCALABLE_PODS.lock().unwrap();
                            scalable_pods.insert(ip.clone(), selector_string.clone());    
                            pod_labels.insert(selectors.clone(), ip.clone());
                            info!("Service {} has no pods, adding to scalable_pods, labels: {:?}", s.name_any(), selectors);
                        }
                    }
                }
            },
        }
    }
    Ok(())
}

fn pod_labels_to_string(selectors: BTreeMap<String, String>) -> String {
    let mut selector_string = String::new();
    for (k, v) in selectors.clone().iter() {
        selector_string.push_str(&format!("{}={},", k, v));
    }
    selector_string.pop(); // remove trailing comma
    selector_string
}
