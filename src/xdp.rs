use redbpf::{HashMap, LruHashMap};
use redbpf::xdp;
use tokio::signal::ctrl_c;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use redbpf::load::Loader;

use probes::xdp::{ClientInfo, LocalInfo};

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/xdp/xdp.elf"
    ))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");
    let probe = loaded.xdp_mut("kern").unwrap();

    probe
        .attach_xdp("eno1", xdp::Flags::default())
        .expect("failed to attach bpf prog");

    let event_fut = async {
        loop {
            let c2l: HashMap<ClientInfo, LocalInfo> = HashMap::new(loaded.map("c2l").unwrap()).unwrap();
            let dst: LruHashMap<[u16; 5], [u16; 5]> = LruHashMap::new(loaded.map("dst").unwrap()).unwrap();

            for (k, v) in c2l.iter() {
                println!("client: {}:{}, local: {}:{}", k.ip, k.port, v.ip, v.port);
            }

            for (k, v) in dst.iter() {
                println!("src: {:?} dest: {:?}", k, v);
            }
            print!("\n\n");

            // for item in c2l {
            //     // println!("client: {}:{}, local: {}:{}", i, estab.get(IPPROTO_UDP), estab.get(IPPROTO_ICMP));
            //     println!("{:?}", item);
            // }
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
