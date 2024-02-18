use anyhow::{Context, Ok};
use futures::{stream, StreamExt, TryStreamExt};
use k8s_openapi::api::apps::v1::{Deployment, StatefulSet};
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::chrono;
use kube::Resource;
use kube::{
    api::Api,
    runtime::{watcher, WatchStreamExt},
    Client, ResourceExt,
};
use log::{info, warn};
use std::collections::HashMap;
use std::thread;

use crate::kubernetes::models::{ServiceData, WorkloadReference, WATCHED_SERVICES};

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
                    && !s
                        .annotations()
                        .contains_key("scale-to-zero.isala.me/scale-down-time")
                {
                    info!(target: "kube_event_watcher", "Service {} is not annotated, skipping", s.name_any());
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
                        target: "kube_event_watcher",
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
                    .parse::<i64>()
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

                        let replicas = deployment
                            .spec
                            .as_ref()
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "Failed to get deployment spec for {}",
                                    deployment.name_any()
                                )
                            })?
                            .replicas
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "Failed to get replicas for {}",
                                    deployment.name_any()
                                )
                            })?;

                        update_workload_status(
                            "deployment".to_string(),
                            deployment.name_any(),
                            deployment.namespace(),
                            replicas,
                            &mut workload_service,
                            s.clone(),
                            service_ip.to_string(),
                            scale_down_time,
                        )
                        .await?;

                        Ok(())
                    }
                    "statefulset" => {
                        let statefulset = statefulsets
                            .get(workload_name)
                            .await
                            .context("Failed to get statefulset")?;

                        let replicas = statefulset
                            .spec
                            .as_ref()
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "Failed to get deployment spec for {}",
                                    statefulset.name_any()
                                )
                            })?
                            .replicas
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "Failed to get replicas for {}",
                                    statefulset.name_any()
                                )
                            })?;

                        update_workload_status(
                            "statefulset".to_string(),
                            statefulset.name_any(),
                            statefulset.namespace(),
                            replicas,
                            &mut workload_service,
                            s.clone(),
                            service_ip.to_string(),
                            scale_down_time,
                        )
                        .await?;

                        Ok(())
                    }
                    _ => Err(anyhow::anyhow!("Unknown workload type: {}", workload_type)),
                };

                if let Err(e) = workload {
                    warn!(target: "kube_event_watcher", "Failed to get workload: {}", e);
                    continue;
                }
            }
            Watched::Deployment(d) => {
                process_resource(d, &workload_service)?;
            }
            Watched::StatefulSet(sts) => {
                process_resource(sts, &workload_service)?;
            }
        }
    }
    Ok(())
}

// Define the common interface
trait K8sResource {
    fn name(&self) -> String;
    fn kind(&self) -> String;
    fn namespace_(&self) -> Option<String>;
    fn replicas(&self) -> Option<i32>;
}

// Implement the interface for Deployment
impl K8sResource for Deployment {
    fn name(&self) -> String {
        self.name_any()
    }

    fn kind(&self) -> String {
        "deployment".to_string()
    }

    fn namespace_(&self) -> Option<String> {
        self.meta().namespace.clone()
    }

    fn replicas(&self) -> Option<i32> {
        let spec = self.spec.as_ref();
        match spec {
            None => None,
            Some(spec) => spec.replicas,
        }
    }
}

// Implement the interface for StatefulSet
impl K8sResource for StatefulSet {
    fn name(&self) -> String {
        self.name_any()
    }

    fn kind(&self) -> String {
        "statefulset".to_string()
    }

    fn namespace_(&self) -> Option<String> {
        self.meta().namespace.clone()
    }

    fn replicas(&self) -> Option<i32> {
        let spec = self.spec.as_ref();
        match spec {
            None => None,
            Some(spec) => spec.replicas,
        }
    }
}

// Now we can define a function that works with any K8sResource
fn process_resource<T: K8sResource>(
    resource: T,
    workload_service: &HashMap<WorkloadReference, Service>,
) -> anyhow::Result<()> {
    let service = workload_service.get(&WorkloadReference {
        kind: resource.kind(),
        name: resource.name(),
        namespace: resource
            .namespace_()
            .ok_or_else(|| anyhow::anyhow!("Failed to get namespace for {}", resource.kind()))?,
    });
    let service = match service {
        Some(s) => s,
        None => return Ok(()),
    };

    let replicas = resource
        .replicas()
        .ok_or_else(|| anyhow::anyhow!("Failed to get replicas for {}", resource.name()))?;

    // TODO: Check if health check is passing before setting backend_available to true
    thread::sleep(std::time::Duration::from_secs(2));

    let service_ip = service
        .spec
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Failed to get service spec for {}", service.name_any()))?
        .cluster_ip
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Failed to get cluster IP for {}", service.name_any()))?;
    {
        let mut watched_services = WATCHED_SERVICES.lock().unwrap();
        let service_data = watched_services.get_mut(service_ip).unwrap();
        service_data.backend_available = replicas >= 1;
    }
    Ok(())
}

async fn update_workload_status(
    kind: String,
    name: String,
    namespace: Option<String>,
    replicas: i32,
    workload_service: &mut HashMap<WorkloadReference, Service>,
    service: Service,
    service_ip: String,
    scale_down_time: i64,
) -> anyhow::Result<()> {
    let namespace = match namespace {
        Some(ns) => ns,
        None => return Err(anyhow::anyhow!("Failed to get namespace for {}", name)),
    };

    info!(target: "update_workload_status", "updating workload status for service: {}, kind: {}, name: {}, namespace: {}, replicas: {}, service_ip: {}, scale_down_time: {}", service.name_any(), kind, name, namespace, replicas, service_ip, scale_down_time);

    // sleep for 1 second to allow the service to be created
    thread::sleep(std::time::Duration::from_secs(2));

    workload_service.insert(
        WorkloadReference {
            kind: kind.clone(),
            name: name.clone(),
            namespace: namespace.clone(),
        },
        service.clone(),
    );
    {
        let mut watched_services = WATCHED_SERVICES.lock().unwrap();

        watched_services.insert(
            service_ip.clone(),
            ServiceData {
                scale_down_time,
                last_packet_time: chrono::Utc::now().timestamp(),
                kind,
                name,
                namespace,
                backend_available: replicas >= 1,
            },
        );
    }

    Ok(())
}
