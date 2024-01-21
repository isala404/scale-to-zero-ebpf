use anyhow::{Context, Ok};
use futures::{stream, StreamExt, TryStreamExt};
use k8s_openapi::api::apps::v1::{Deployment, StatefulSet};
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::chrono;
use k8s_openapi::serde_json::json;
use kube::api::{Patch, PatchParams};
use kube::{
    api::Api,
    runtime::{watcher, WatchStreamExt},
    Client, ResourceExt,
};
use log::{info, warn};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, Duration};

// This contains a mapper of service IPs to availablity of it's backends
// If pods are available, the value is true, if not, false
pub static WATCHED_SERVICES: Lazy<Arc<Mutex<HashMap<String, ServiceData>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

#[derive(Eq, Hash, PartialEq)]
struct WorkloadReference {
    kind: String,
    name: String,
    namespace: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServiceData {
    pub scale_down_time: u64,
    pub last_packet_time: i64,
    pub kind: String,
    pub name: String,
    pub namespace: String,
    pub backend_available: bool,
}

pub async fn kube_event_watcher() -> anyhow::Result<()> {
    // Workload (deploy/statefulset) to service mapper
    let mut workload_service: HashMap<WorkloadReference, Service> = HashMap::new();

    let client = Client::try_default().await?;

    let services: Api<Service> = Api::default_namespaced(client.clone());
    let deployments: Api<Deployment> = Api::default_namespaced(client.clone());
    let statefulsets: Api<StatefulSet> = Api::default_namespaced(client.clone());

    let svc_watcher = watcher(services, watcher::Config::default());
    let deployment_watcher = watcher(deployments.clone(), watcher::Config::default());
    let statefulset_watcher = watcher(statefulsets.clone(), watcher::Config::default());

    // select on applied events from all watchers
    let mut combo_stream = stream::select_all(vec![
        svc_watcher
            .applied_objects()
            .map_ok(Watched::Service)
            .boxed(),
        deployment_watcher
            .applied_objects()
            .map_ok(Watched::Deployment)
            .boxed(),
        statefulset_watcher
            .applied_objects()
            .map_ok(Watched::StatefulSet)
            .boxed(),
    ]);
    // SelectAll Stream elements must have the same Item, so all packed in this:
    #[allow(clippy::large_enum_variant)]
    enum Watched {
        Service(Service),
        Deployment(Deployment),
        StatefulSet(StatefulSet),
    }
    while let Some(o) = combo_stream.try_next().await? {
        match o {
            Watched::Service(s) => {
                // ignore services that don't have the annotation
                if !s
                    .annotations()
                    .contains_key("scale-to-zero.isala.me/reference")
                    && !s.annotations().contains_key("idle-minutes")
                {
                    info!("Service {} is not annotated, skipping", s.name_any());
                    continue;
                }

                // Get the workload reference from the annotation
                let workload_ref = s
                    .annotations()
                    .get("scale-to-zero.isala.me/reference")
                    .unwrap()
                    .clone();
                let workload_ref_split: Vec<&str> = workload_ref.split('/').collect();

                if workload_ref_split.len() != 2 {
                    warn!(
                        "Service {} has invalid reference annotation: {}",
                        s.name_any(),
                        workload_ref
                    );
                    continue;
                }
                let workload_type = workload_ref_split[0];
                let workload_name = workload_ref_split[1];

                // Get the idle minutes from the annotation
                let scale_down_time = s
                    .annotations()
                    .get("scale-to-zero.isala.me/scale-down-time")
                    .unwrap()
                    .parse::<u64>()
                    .context("Failed to parse scale-down-time")?;


                let service_ip = s
                    .spec
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow::anyhow!("Failed to get service spec for {}", s.name_any())
                    })?
                    .cluster_ip
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow::anyhow!("Failed to get cluster IP for {}", s.name_any())
                    })?;

                info!(target: "kube_watcher", "service: {}, workload_type: {}, workload_name: {}, scale_down_time: {}, service_ip: {}", s.name_any(), workload_type, workload_name, scale_down_time, service_ip);

                let workload = match workload_type {
                    "deployment" => {
                        let deployment = deployments
                            .get(workload_name)
                            .await
                            .context("Failed to get deployment")?;
                        workload_service.insert(
                            WorkloadReference {
                                kind: "deployment".to_string(),
                                name: workload_name.to_string(),
                                namespace: deployment.namespace().ok_or_else(|| {
                                    anyhow::anyhow!("Failed to get namespace for deployment")
                                })?,
                            },
                            s.clone(),
                        );

                        let spec = deployment.spec.as_ref().ok_or_else(|| {
                            anyhow::anyhow!(
                                "Failed to get deployment spec for {}",
                                deployment.name_any()
                            )
                        })?;
                        let replicas = spec.replicas.ok_or_else(|| {
                            anyhow::anyhow!("Failed to get replicas for {}", deployment.name_any())
                        })?;
                        {
                            let mut watched_services = WATCHED_SERVICES.lock().unwrap();
                            watched_services.insert(
                                service_ip.clone(),
                                ServiceData {
                                    scale_down_time,
                                    last_packet_time: chrono::Utc::now().timestamp(),
                                    kind: "deployment".to_string(),
                                    name: deployment.name_any(),
                                    namespace: deployment.namespace().ok_or_else(|| {
                                        anyhow::anyhow!("Failed to get namespace for deployment")
                                    })?,
                                    backend_available: replicas >= 1,
                                },
                            );
                        }

                        Ok(())
                    }
                    "statefulset" => {
                        let statefulset = statefulsets
                            .get(workload_name)
                            .await
                            .context("Failed to get statefulset")?;
                        workload_service.insert(
                            WorkloadReference {
                                kind: "statefulset".to_string(),
                                name: workload_name.to_string(),
                                namespace: statefulset.namespace().ok_or_else(|| {
                                    anyhow::anyhow!("Failed to get namespace for statefulset")
                                })?,
                            },
                            s.clone(),
                        );

                        let spec = statefulset.spec.as_ref().ok_or_else(|| {
                            anyhow::anyhow!(
                                "Failed to get statefulset spec for {}",
                                statefulset.name_any()
                            )
                        })?;
                        let replicas = spec.replicas.ok_or_else(|| {
                            anyhow::anyhow!("Failed to get replicas for {}", statefulset.name_any())
                        })?;

                        {
                            let mut watched_services = WATCHED_SERVICES.lock().unwrap();
                            watched_services.insert(
                                service_ip.clone(),
                                ServiceData {
                                    scale_down_time,
                                    last_packet_time: chrono::Utc::now().timestamp(),
                                    kind: "statefulset".to_string(),
                                    name: statefulset.name_any(),
                                    namespace: statefulset.namespace().ok_or_else(|| {
                                        anyhow::anyhow!("Failed to get namespace for statefulset")
                                    })?,
                                    backend_available: replicas >= 1,
                                },
                            );
                        }

                        Ok(())
                    }
                    _ => Err(anyhow::anyhow!("Unknown workload type: {}", workload_type)),
                };

                if let Err(e) = workload {
                    warn!("Failed to get workload: {}", e);
                    continue;
                }
            }
            Watched::Deployment(d) => {
                let service = workload_service.get(&WorkloadReference {
                    kind: "deployment".to_string(),
                    name: d.name_any(),
                    namespace: d
                        .namespace()
                        .ok_or_else(|| anyhow::anyhow!("Failed to get namespace for deployment"))?,
                });
                let service = match service {
                    Some(s) => s,
                    None => continue,
                };

                let spec = d.spec.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Failed to get deployment spec for {}", d.name_any())
                })?;

                let replicas = spec.replicas.ok_or_else(|| {
                    anyhow::anyhow!("Failed to get replicas for {}", d.name_any())
                })?;

                let service_ip = service
                    .spec
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow::anyhow!("Failed to get service spec for {}", service.name_any())
                    })?
                    .cluster_ip
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow::anyhow!("Failed to get cluster IP for {}", service.name_any())
                    })?;

                {
                    let mut watched_services = WATCHED_SERVICES.lock().unwrap();
                    let service_data = watched_services.get_mut(service_ip).unwrap();
                    service_data.backend_available = replicas >= 1;
                }
            }
            Watched::StatefulSet(sts) => {
                let service = workload_service.get(&WorkloadReference {
                    kind: "statefulset".to_string(),
                    name: sts.name_any(),
                    namespace: sts.namespace().ok_or_else(|| {
                        anyhow::anyhow!("Failed to get namespace for statefulset")
                    })?,
                });
                let service = match service {
                    Some(s) => s,
                    None => continue,
                };

                let spec = sts.spec.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Failed to get statefulset spec for {}", sts.name_any())
                })?;

                let replicas = spec.replicas.ok_or_else(|| {
                    anyhow::anyhow!("Failed to get replicas for {}", sts.name_any())
                })?;

                let service_ip = service
                    .spec
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow::anyhow!("Failed to get service spec for {}", service.name_any())
                    })?
                    .cluster_ip
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow::anyhow!("Failed to get cluster IP for {}", service.name_any())
                    })?;

                {
                    let mut watched_services = WATCHED_SERVICES.lock().unwrap();
                    let service_data = watched_services.get_mut(service_ip).unwrap();
                    service_data.backend_available = replicas >= 1;
                }
            }
        }
    }
    Ok(())
}

pub async fn scale_down() -> anyhow::Result<()> {
    let client = Client::try_default().await?;
    let deployments: Api<Deployment> = Api::default_namespaced(client.clone());
    let statefulsets: Api<StatefulSet> = Api::default_namespaced(client.clone());
    loop {
        let keys: Vec<_>;
        {
            let watched_services = WATCHED_SERVICES.lock().unwrap();
            keys = watched_services.keys().cloned().collect();
        }
        for key in keys {
            let mut service: ServiceData;
            {
                let mut watched_services = WATCHED_SERVICES.lock().unwrap();
                service = watched_services.get_mut(&key).unwrap().clone();
            }
            let idle_minutes = service.scale_down_time;
            let last_packet_time = service.last_packet_time;
            let now = chrono::Utc::now().timestamp();
            if now - last_packet_time > idle_minutes as i64 && service.backend_available {
                service.backend_available = false;
                info!(target: "scale_down", "Scaling down service {}", service.name);
                if service.kind == "deployment" {
                    deployments
                        .patch(
                            service.name.as_str(),
                            &PatchParams::default(),
                            &Patch::Merge(json!({
                                "spec": {
                                    "replicas": 0
                                }
                            })),
                        )
                        .await?;
                } else if service.kind == "statefulset" {
                    statefulsets
                        .patch(
                            service.name.as_str(),
                            &PatchParams::default(),
                            &Patch::Merge(json!({
                                "spec": {
                                    "replicas": 0
                                }
                            })),
                        )
                        .await?;
                }
                {
                    let mut watched_services = WATCHED_SERVICES.lock().unwrap();
                    let service_to_update = watched_services.get_mut(&key).unwrap();
                    *service_to_update = service;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

static LAST_CALLED: Lazy<Mutex<HashMap<String, SystemTime>>> = Lazy::new(|| Mutex::new(HashMap::new()));


pub async fn scale_up(service_ip: String) -> anyhow::Result<()> {
    let now = SystemTime::now();
    info!(target: "scale_up", "Scaling up service {}", service_ip);
    {
        let mut last_called = LAST_CALLED.lock().unwrap();
        if let Some(time) = last_called.get(&service_ip) {
            if now.duration_since(*time)? < Duration::from_secs(5) {
                return Err(anyhow::anyhow!("Rate Limited: Function can only be called once every 5 seconds per service_ip"));
            }
        }
        last_called.insert(service_ip.clone(), now);
    }



    let client = Client::try_default().await?;
    let deployments: Api<Deployment> = Api::default_namespaced(client.clone());
    let statefulsets: Api<StatefulSet> = Api::default_namespaced(client.clone());
    let mut service: ServiceData;
    {
        let mut watched_services = WATCHED_SERVICES.lock().unwrap();
        service = watched_services.get_mut(&service_ip).unwrap().clone();
    }
    service.backend_available = true;

    if service.kind == "deployment" {
        deployments
            .patch(
                service.name.as_str(),
                &PatchParams::default(),
                &Patch::Merge(json!({
                    "spec": {
                        "replicas": 1
                    }
                })),
            )
            .await?;
    } else if service.kind == "statefulset" {
        statefulsets
            .patch(
                service.name.as_str(),
                &PatchParams::default(),
                &Patch::Merge(json!({
                    "spec": {
                        "replicas": 1
                    }
                })),
            )
            .await?;
    }
    Ok(())
}
