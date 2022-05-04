use redbpf::HashMap;
use tokio::signal::ctrl_c;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use redbpf_probes::socket_filter::prelude::*;
use redbpf::load::Loader;

use probes::map_poc::Socket;

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/map_poc/map_poc.elf"
    ))
}


#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");
    let probe = loaded.socket_filter_mut("entry").unwrap();

    probe
        .attach_socket_filter("lo")
        .expect("error on SocketFilter::attach_socket_filter");

    let event_fut = async {
        loop {
            let c2l: HashMap<Socket, i32> = HashMap::new(loaded.map("SocketMapping").unwrap()).unwrap();

            for (k, v) in c2l.iter() {
                println!("s1: {:?}, s2: {:?}", k, v);
            }

            // for item in c2l {
            //     // println!("client: {}:{}, local: {}:{}", i, estab.get(IPPROTO_UDP), estab.get(IPPROTO_ICMP));
            //     println!("{:?}", item);
            // }
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
    // let estab: HashMap<u32, u32> = HashMap::new(loaded.map("COUNTER").unwrap()).unwrap();
    // for (k, v) in estab.iter() {
    //     println!("{} {}", k, v);
    // }
}
