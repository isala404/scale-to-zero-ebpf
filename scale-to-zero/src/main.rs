use aya::{
    include_bytes_aligned,
    maps::{perf::AsyncPerfEventArray, HashMap},
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Bpf,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn, debug};
use scale_to_zero_common::PacketLog;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use tokio::task;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    #[clap(short, long, default_value = "default")]
    attach_mode: String,
}

mod kube_watcher;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    task::spawn(async move {
        kube_watcher::kube_event_watcher().await.unwrap();
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

    let attach_mode = opt.attach_mode.as_str();

    if attach_mode == "default" {
        program.attach(&opt.iface, XdpFlags::default())?;
    } else if attach_mode == "skb" {
        program.attach(&opt.iface, XdpFlags::SKB_MODE)?;
    } else if attach_mode == "hw" {
        program.attach(&opt.iface, XdpFlags::HW_MODE)?;
    } else {
        panic!("Unknown attach mode: {}", attach_mode);
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
                    let src_addr = Ipv4Addr::from(data.ipv4_address);
                    info!("LOG: DST {}, ACTION {}", src_addr, data.action);
                }
            }
        });
    }

    // sync scalable_service_list with SCALABLE_PODS
    let mut scalable_service_list: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("SERVICE_LIST").unwrap()).unwrap();
    loop {
        let pod_ips = kube_watcher::SCALABLE_PODS.lock().unwrap();
        let new_ips: HashSet<u32> = pod_ips.iter().map(|(ip, _)| ip.parse::<Ipv4Addr>().unwrap().into()).collect();

        for ip in new_ips.clone() {
            let _ = scalable_service_list.insert(ip, 0, 0);
            debug!("Added {} to scalable_service_list", ip);
        }

        // Collect keys to remove
        let mut keys_to_remove: Vec<u32> = Vec::new();
        for key in scalable_service_list.keys() {
            let ip = key.unwrap();
            if !new_ips.contains(&ip) {
                keys_to_remove.push(ip);
            }
        }

        // Remove keys
        for ip in keys_to_remove {
            scalable_service_list.remove(&ip).unwrap();
            debug!("Removed {} from scalable_service_list", ip);
        }

        drop(pod_ips);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
