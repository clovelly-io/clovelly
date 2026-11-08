//! The egress proxy as its own process (criterion 13, locally): the supervisor starts
//! the real `egress-proxy` binary, and a `kill -9` of it costs the sandbox a gap in its
//! egress, not its CA, its credentials, the lines already logged or the egress count.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::cred::{AdapterType, Binding, CredName, Secret};
use common::ids::SandboxId;
use egress_proxy::{Credential, Network, Ports, Supervisor, SupervisorConfig, testing};

type Events = Arc<Mutex<Vec<(String, serde_json::Value)>>>;

async fn supervisor() -> (Arc<Supervisor>, Events) {
    let events: Events = Arc::default();
    let seen = Arc::clone(&events);
    let sup = Supervisor::start(SupervisorConfig {
        bin: env!("CARGO_BIN_EXE_egress-proxy").into(),
        roots_pem: testing::TestCa::new().pem(),
        cell: "test".into(),
        network: Network {
            listen: Ipv4Addr::LOCALHOST,
            ports: Ports { tls: 0, http: 0, dns: 0, connect: 0 },
            hosts: HashMap::from([("dest.test".parse().unwrap(), vec![Ipv4Addr::LOCALHOST])]),
            exempt: vec![Ipv4Addr::LOCALHOST],
        },
        status: Box::new(move |state, detail| seen.lock().unwrap().push((state.to_owned(), detail))),
    })
    .await
    .unwrap();
    (sup, events)
}

fn credential(secret: &str) -> HashMap<CredName, Credential> {
    let name: CredName = "svc".parse().unwrap();
    let binding = Binding { name: name.clone(), adapter: AdapterType::Bearer, destination: "dest.test".parse().unwrap() };
    HashMap::from([(name, Credential { binding, secret: Secret::copy_from(secret.as_bytes()).unwrap() })])
}

/// Waits up to 5 s for `ready`.
async fn until(mut ready: impl FnMut() -> bool) {
    for _ in 0..500 {
        if ready() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("not within 5 s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_killed_proxy_comes_back_with_the_same_ca_and_the_log_records_the_gap() {
    let (sup, events) = supervisor().await;
    let (port, seen) = testing::destination().await;
    let policy = testing::policy(&format!(r#"[{{"host":"dest.test","port":{port},"adapter":{{"type":"bearer","credential":"svc"}}}}]"#));
    sup.register(Ipv4Addr::LOCALHOST, SandboxId::generate(), policy, credential("REAL-SECRET")).await.unwrap();

    let connect = SocketAddr::from((Ipv4Addr::LOCALHOST, sup.ports().connect));
    let target = format!("dest.test:{port}");
    let request = format!("GET / HTTP/1.1\r\nHost: {target}\r\nAuthorization: Bearer clovelly://cred/svc\r\nConnection: close\r\n\r\n");
    let before = testing::through(connect, &target, &request).await.unwrap();
    assert!(before.ends_with("ok"), "{before}");
    assert!(seen.lock().unwrap()[0].contains("Bearer REAL-SECRET\r\n"));
    until(|| sup.log(Ipv4Addr::LOCALHOST).is_some_and(|l| l.count == 1)).await;
    // Phase 10: the egress count, reported each second. The head goes out with the
    // placeholder (19 bytes) replaced by the secret (11).
    let one = request.len() as u64 - 8;
    until(|| sup.egress_bytes() == one).await;

    let (ca, pid) = (sup.ca_pem(), sup.pid().unwrap());
    let killed = std::process::Command::new("kill").args(["-9", &pid.to_string()]).status().unwrap();
    assert!(killed.success());
    until(|| sup.restarts() == 1 && sup.pid().is_some_and(|p| p != pid)).await;
    until(|| events.lock().unwrap().iter().any(|(s, _)| s == "proxy-restarted")).await;
    assert_eq!(sup.ca_pem(), ca, "sandboxes re-trust nothing");
    assert_eq!(sup.ports().connect, connect.port(), "the same ports");

    let after = testing::through(connect, &target, &request).await.unwrap();
    assert!(after.ends_with("ok"), "{after}");
    assert!(seen.lock().unwrap()[1].contains("Bearer REAL-SECRET\r\n"), "the credential was handed over again");

    until(|| sup.log(Ipv4Addr::LOCALHOST).is_some_and(|l| l.count == 2)).await;
    until(|| sup.egress_bytes() == 2 * one).await;
    let log = sup.unregister(Ipv4Addr::LOCALHOST).await.unwrap();
    assert_eq!(log.count, 2, "the line from before the kill is kept: {:?}", log.lines);
    assert!(log.lines.iter().all(|l| l.contains(r#""credential":"svc""#) && !l.contains("REAL-SECRET")), "{:?}", log.lines);
    assert_eq!(log.gaps.len(), 1);
    assert!(log.gaps[0].from <= log.gaps[0].to);
    let events = events.lock().unwrap();
    let exited = events.iter().find(|(s, _)| s == "proxy-exited").unwrap();
    assert_eq!(exited.1["sandboxes"], 1, "{exited:?}");
    let restarted = events.iter().find(|(s, _)| s == "proxy-restarted").unwrap();
    assert!(restarted.1["recovery_ms"].as_u64().unwrap() < 5000, "{restarted:?}");
    assert!(sup.log(Ipv4Addr::LOCALHOST).is_none());
}

/// A registration returns once the process holds the sandbox; a second one at the same
/// address is refused; an unregistered address has no log.
#[tokio::test]
async fn registrations_are_acknowledged() {
    let (sup, _) = supervisor().await;
    let policy = testing::policy(r#"[{"host":"dest.test","port":443}]"#);
    sup.register(Ipv4Addr::LOCALHOST, SandboxId::generate(), Arc::clone(&policy), HashMap::new()).await.unwrap();
    let again = sup.register(Ipv4Addr::LOCALHOST, SandboxId::generate(), policy, HashMap::new()).await;
    assert!(matches!(again, Err(egress_proxy::SupervisorError::Busy(_))), "{again:?}");
    let log = sup.unregister(Ipv4Addr::LOCALHOST).await.unwrap();
    assert!(log.gaps.is_empty() && log.count == 0);
    assert!(sup.unregister(Ipv4Addr::LOCALHOST).await.is_none());
}
