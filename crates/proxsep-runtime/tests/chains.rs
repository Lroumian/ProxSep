use proxsep_core::{
    profile::{Action, Chain, Profile, Proxy},
    rules::Connection,
};
use proxsep_runtime::Runtime;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
#[tokio::test]
async fn sequential_chain_reaches_each_hop_and_transfers_payload() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let (mut r, mut w) = s.split();
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });
    let a = Runtime::new(Profile::default());
    let b = Runtime::new(Profile::default());
    let ha = a.start_socks5("127.0.0.1:0", "hop-a".into()).await.unwrap();
    let hb = b.start_socks5("127.0.0.1:0", "hop-b".into()).await.unwrap();
    let mut p = Profile {
        proxies: vec![
            Proxy {
                id: 1,
                port: ha.local_addr().port(),
                ..Proxy::default()
            },
            Proxy {
                id: 2,
                port: hb.local_addr().port(),
                ..Proxy::default()
            },
        ],
        chains: vec![Chain {
            id: 3,
            proxy_ids: vec![1, 2],
            ..Chain::default()
        }],
        ..Profile::default()
    };
    p.rules[0].action = Action::Chain("3".into());
    let runtime = Runtime::new(p);
    let mut stream = runtime
        .connect(&Connection::new("app", "127.0.0.1", target.port()))
        .await
        .unwrap();
    stream.write_all(b"multi-hop").await.unwrap();
    let mut reply = [0; 9];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"multi-hop");
    assert_eq!(a.events()[0].port, hb.local_addr().port());
    assert_eq!(b.events()[0].port, target.port());
    ha.stop().await;
    hb.stop().await;
}
