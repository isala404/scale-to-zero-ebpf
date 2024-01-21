use aya::{
    maps::{perf::AsyncPerfEventArray, HashMap},
    programs::{Xdp, XdpFlags},
    util::online_cpus,
};
use bytes::BytesMut;
use log::{info, warn};
use network_interface::NetworkInterface;
use network_interface::NetworkInterfaceConfig;
use scale_to_zero_common::PacketLog;
use tokio::task;

mod kubernetes;
mod utils;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Start kubernetes event watcher in background
    task::spawn(async move {
        kubernetes::controller::kube_event_watcher().await.unwrap();
    });

    // Start kubernetes scaler in background
    task::spawn(async move {
        kubernetes::scaler::scale_down().await.unwrap();
    });

    let mut bpf = utils::load_ebpf_code()?;

    let program: &mut Xdp = bpf
        .program_mut("xdp_scale_to_zero_fw")
        .unwrap()
        .try_into()?;
    program.load()?;

    // Deploy eBPF program to all network interfaces
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

    // Initialize perf event array to receive messages from eBPF program
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("SCALE_REQUESTS").unwrap())?;

    // Poll perf event array in background
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
                    utils::process_packet(data).await;
                }
            }
        });
    }

    // sync scalable_service_list with SCALABLE_PODS
    let mut scalable_service_list: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("SERVICE_LIST").unwrap()).unwrap();
    loop {
        utils::sync_data(&mut scalable_service_list).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
