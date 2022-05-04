use redbpf::{Array, HashMap};
use tokio::signal::ctrl_c;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use redbpf_probes::socket_filter::prelude::*;

use redbpf::load::Loader;

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/openmonitor/openmonitor.elf"
    ))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");
    let probe = loaded.socket_filter_mut("probe").unwrap();

    probe
        .attach_socket_filter("eno1")
        .expect("error on SocketFilter::attach_socket_filter");

    let event_fut = async {
        loop {
            let estab: HashMap<u32, u32> = HashMap::new(loaded.map("COUNTER").unwrap()).unwrap();

            println!("TCP: {:?} ICMP: {:?}", estab.get(IPPROTO_TCP), estab.get(IPPROTO_ICMP));
            print!("\n\n");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    };
    let ctrlc_fut = async {
        ctrl_c().await.unwrap();
    };
    tokio::select! {
        _ = event_fut => {

        }
        _ = ctrlc_fut => {
            println!("quit");
        }
    }
    let estab: HashMap<u32, u32> = HashMap::new(loaded.map("COUNTER").unwrap()).unwrap();
    for (k, v) in estab.iter() {
        println!("{} {}", k, v);
    }
}
