use aya::{
    include_bytes_aligned,
    maps::{perf::AsyncPerfEventArray, HashMap},
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Bpf,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use k8s_openapi::chrono;
use log::{error, info, warn};
use network_interface::NetworkInterface;
use network_interface::NetworkInterfaceConfig;
use scale_to_zero_common::PacketLog;
use std::net::Ipv4Addr;
use tokio::task;

mod kube_watcher;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    task::spawn(async move {
        kube_watcher::kube_event_watcher().await.unwrap();
    });

    task::spawn(async move {
        kube_watcher::scale_down().await.unwrap();
    });

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/scale-to-zero"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/scale-to-zero"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf
        .program_mut("xdp_scale_to_zero_fw")
        .unwrap()
        .try_into()?;
    program.load()?;

    let network_interfaces = NetworkInterface::show().unwrap();
    let network_interfaces = network_interfaces
        .iter()
        .map(|itf| itf.name.clone())
        .collect::<Vec<_>>();

    // let attach_modes = [XdpFlags::default(), XdpFlags::SKB_MODE, XdpFlags::HW_MODE];
    for itf in network_interfaces.iter() {
        info!("Attach to interface {} with {:?}", itf, XdpFlags::SKB_MODE);
        match program.attach(&itf, XdpFlags::SKB_MODE) {
            Ok(_) => {}
            Err(err) => {
                warn!("Failed to detach from interface {}: {}", itf, err);
            }
        }
    }

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("SCALE_REQUESTS").unwrap())?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };
                    let dist_addr = Ipv4Addr::from(data.ipv4_address);
                    if dist_addr.is_loopback() {
                        continue;
                    }

                    {
                        let mut services = kube_watcher::WATCHED_SERVICES.lock().unwrap();

                        match services.get_mut(&dist_addr.to_string()) {
                            Some(service) => {
                                service.last_packet_time = chrono::Utc::now().timestamp();
                            }
                            None => {}
                        }
                    }
                    if data.action == 1 {
                        match kube_watcher::scale_up(dist_addr.to_string()).await {
                            Ok(_) => {
                                info!("Scaled up {}", dist_addr);
                            }
                            Err(err) => {
                                if !err.to_string().starts_with("Rate Limited: Function ") {
                                    error!("Failed to scale up {}: {}", dist_addr, err);
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    // sync scalable_service_list with SCALABLE_PODS
    let mut scalable_service_list: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("SERVICE_LIST").unwrap()).unwrap();
    loop {
        // debug!("Sync service list");
        let pod_ips: std::collections::HashMap<u32, u32> = kube_watcher::WATCHED_SERVICES
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| {
                (
                    k.parse::<Ipv4Addr>().unwrap().into(),
                    v.backend_available as u32,
                )
            })
            .collect();

        for (key, value) in pod_ips.clone() {
            match scalable_service_list.get(&key, 0) {
                Ok(old_value) => {
                    if old_value != value {
                        let _ = scalable_service_list.insert(key, value, 0);
                        info!("Update service list: {:?} {}", key, value)
                    }
                }
                Err(_) => {
                    let _ = scalable_service_list.insert(key, value, 0);
                    info!("Add service list: {:?} {}", key, value)
                }
            }
        }

        let keys: Vec<_> = scalable_service_list.keys().collect();
        for key in keys {
            match key {
                Ok(ip) => {
                    if !pod_ips.contains_key(&ip) {
                        let _ = scalable_service_list.remove(&ip);
                        info!("Remove service list: {:?}", ip)
                    }
                }
                Err(err) => {
                    info!("Error: {:?}", err);
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
