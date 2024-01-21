use super::models::{ServiceData, WATCHED_SERVICES};
use crate::kubernetes::models::LAST_CALLED;
use anyhow::Ok;
use k8s_openapi::api::apps::v1::{Deployment, StatefulSet};
use k8s_openapi::chrono;
use k8s_openapi::serde_json::json;
use kube::api::Api;
use kube::api::{Patch, PatchParams};
use kube::Client;
use log::info;
use std::time::{Duration, SystemTime};

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
                info!(target: "scale_down", "Scaling down backends of {}", service.name);
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

pub async fn scale_up(service_ip: String) -> anyhow::Result<()> {
    let now = SystemTime::now();
    {
        let mut last_called = LAST_CALLED.lock().unwrap();
        if let Some(time) = last_called.get(&service_ip) {
            if now.duration_since(*time)? < Duration::from_secs(5) {
                return Err(anyhow::anyhow!(
                    "Rate Limited: Function can only be called once every 5 seconds per service_ip"
                ));
            }
        }
        last_called.insert(service_ip.clone(), now);
    }
    info!(target: "scale_up", "Scaling up backends of {}", service_ip);

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
