//! The `egress-proxy` process: reads [`ToProxy`] frames from the agent, serves the
//! sandboxes it registers with one [`Proxy`], and writes [`FromProxy`] frames back
//! ([`crate::ipc`]). It holds the in-cell CA's key, the policies and the released
//! credentials, and nothing else of the cell's: no DEK, no cell key. It ends when the
//! agent's end of the channel closes (the agent died, or is replacing it).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::bundle::{BundleError, HostName, HostNameError, Policy};
use common::cred::{Binding, CredError, CredName, Secret};
use common::ids::{IdError, SandboxId};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::ipc::{self, Blob, FromProxy, IpcError, ToProxy, WireCredential};
use crate::{CellCa, Config, Credential, Guard, Listeners, Proxy, SandboxEgress, TlsError, drained};

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error(transparent)]
    Ipc(#[from] IpcError),
    #[error("the agent's first message was not Hello")]
    NoHello,
    #[error("the agent sent Hello twice")]
    SecondHello,
    #[error("Hello: CA certificate: {0}")]
    CaCert(common::b64::Base64Error),
    #[error("Hello: fixed host: {0}")]
    Host(HostNameError),
    #[error("in-cell CA: {0}")]
    Ca(#[from] TlsError),
    #[error("listening: {0}")]
    Listen(std::io::Error),
    #[error("a listener failed: {0}")]
    Serving(std::io::Error),
}

/// Why a sandbox could not be registered (sent to the agent as [`FromProxy::Refused`]).
#[derive(Debug, thiserror::Error)]
enum RegisterError {
    #[error("sandbox id: {0}")]
    Id(#[from] IdError),
    #[error("bundle: {0}")]
    Encoding(#[from] common::b64::Base64Error),
    #[error(transparent)]
    Bundle(#[from] BundleError),
    #[error("credential: {0}")]
    Credential(#[from] CredError),
    #[error("credential destination: {0}")]
    Destination(#[from] HostNameError),
    #[error("the credentials' lengths do not add up to the secret part")]
    Secrets,
}

/// Runs the proxy process on `input` (the agent's frames) and `output` (to the agent)
/// until `input` ends.
pub async fn run<R, W>(mut input: R, output: W) -> Result<(), ProcessError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let Some((ToProxy::Hello { cell, ca_cert, roots_pem, listen, ports, hosts, exempt }, key)) = ipc::read(&mut input).await? else {
        return Err(ProcessError::NoHello);
    };
    let cert = common::b64::decode(&ca_cert).map_err(ProcessError::CaCert)?;
    let ca = CellCa::from_key(&cell, key.as_slice(), &cert)?;
    drop(key);
    let hosts = hosts
        .into_iter()
        .map(|(name, ips)| Ok((name.parse::<HostName>()?, ips)))
        .collect::<Result<HashMap<_, _>, HostNameError>>()
        .map_err(ProcessError::Host)?;
    let listeners = Listeners::bind(listen, ports).await.map_err(ProcessError::Listen)?;
    let bound = listeners.ports().map_err(ProcessError::Listen)?;
    let proxy = Proxy::with_ca(
        Config { roots_pem, guard: Arc::new(Guard::with_exempt(exempt)), ports: bound, cell, hosts },
        ca,
    )?;
    let (events, outgoing) = mpsc::unbounded_channel();
    let mut writer = tokio::spawn(write_events(output, outgoing));
    let mut serving = tokio::spawn({
        let p = proxy.clone();
        async move { p.serve_on(listeners).await }
    });
    let _ = events.send(FromProxy::Ready { ports: bound });
    let ticker = tokio::spawn(count_connections(proxy.clone(), events.clone()));
    let result = loop {
        // Only an exit ends the read part way through a frame.
        tokio::select! {
            frame = ipc::read::<_, ToProxy>(&mut input) => match frame {
                Ok(Some((msg, secret))) => {
                    if let Err(e) = handle(&proxy, &events, msg, secret) {
                        break Err(e);
                    }
                }
                Ok(None) => break Ok(()),
                Err(e) => break Err(e.into()),
            },
            r = &mut serving => break match r {
                Ok(Err(e)) => Err(ProcessError::Serving(e)),
                _ => Ok(()),
            },
            // The agent stopped reading: it is gone.
            _ = &mut writer => break Ok(()),
        }
    };
    ticker.abort();
    serving.abort();
    result
}

fn handle(proxy: &Proxy, events: &mpsc::UnboundedSender<FromProxy>, msg: ToProxy, secret: Blob) -> Result<(), ProcessError> {
    match msg {
        ToProxy::Hello { .. } => return Err(ProcessError::SecondHello),
        ToProxy::AddOwn { ip } => proxy.guard().add_own(ip),
        ToProxy::Register { ip, sandbox, bundle, ceiling, credentials } => {
            let send = events.clone();
            let id = sandbox.clone();
            let lines = move |line| {
                let _ = send.send(FromProxy::Log { ip, sandbox: id.clone(), line });
            };
            let event = match parse_register(&sandbox, &bundle, ceiling.into(), &credentials, &secret, lines) {
                Ok(egress) => {
                    proxy.register(ip, egress);
                    FromProxy::Registered { ip, sandbox }
                }
                Err(e) => FromProxy::Refused { ip, sandbox, reason: e.to_string() },
            };
            let _ = events.send(event);
        }
        ToProxy::Unregister { ip, sandbox } => {
            // Ended now, in frame order, so a later Register at `ip` is never undone.
            let ended = proxy.end(ip);
            let events = events.clone();
            tokio::spawn(async move {
                // Every connection records (sends) its line before it lets go of the
                // sandbox, so this follows the sandbox's last line.
                if let Some(e) = ended {
                    drained(e).await;
                }
                let _ = events.send(FromProxy::Unregistered { ip, sandbox });
            });
        }
    }
    Ok(())
}

/// A sandbox from a Register frame, its log lines handed to `lines`: its id, its policy,
/// and its credentials, each secret copied from `secret` (wiped when dropped) into its
/// own [`Secret`].
fn parse_register(
    sandbox: &str,
    bundle: &str,
    ceiling: common::sandbox::Size,
    wire: &[WireCredential],
    secret: &Blob,
    lines: impl Fn(String) + Send + Sync + 'static,
) -> Result<SandboxEgress, RegisterError> {
    let id: SandboxId = sandbox.parse()?;
    let policy = Arc::new(Policy::parse_trusted(&common::b64::decode(bundle)?, ceiling)?);
    let mut credentials = HashMap::with_capacity(wire.len());
    let mut at = 0usize;
    for c in wire {
        let end = at.checked_add(c.len).ok_or(RegisterError::Secrets)?;
        let bytes = secret.as_slice().get(at..end).ok_or(RegisterError::Secrets)?;
        at = end;
        let name: CredName = c.name.parse()?;
        let binding = Binding { name: name.clone(), adapter: c.adapter, destination: c.destination.parse()? };
        credentials.insert(name, Credential { binding, secret: Secret::copy_from(bytes)? });
    }
    if at != secret.len() {
        return Err(RegisterError::Secrets);
    }
    Ok(SandboxEgress::streamed(id, policy, credentials, lines))
}

async fn write_events<W: AsyncWrite + Unpin>(mut w: W, mut events: mpsc::UnboundedReceiver<FromProxy>) -> Result<(), IpcError> {
    while let Some(e) = events.recv().await {
        ipc::write(&mut w, &e, &[]).await?;
    }
    Ok(())
}

async fn count_connections(proxy: Proxy, events: mpsc::UnboundedSender<FromProxy>) {
    let mut every = tokio::time::interval(Duration::from_secs(1));
    loop {
        every.tick().await;
        if events.send(FromProxy::Connections { count: proxy.connections(), egress_bytes: proxy.egress_bytes() }).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::ipc::Ceiling;
    use crate::{CaKey, Ports, testing};
    use common::cred::AdapterType;
    use tokio::io::AsyncWriteExt;

    fn hello(ca: &CaKey) -> ToProxy {
        ToProxy::Hello {
            cell: "test".into(),
            ca_cert: common::b64::encode(ca.cert_der()),
            roots_pem: testing::TestCa::new().pem(),
            listen: Ipv4Addr::LOCALHOST,
            ports: Ports { tls: 0, http: 0, dns: 0, connect: 0 },
            hosts: HashMap::from([("dest.test".to_owned(), vec![Ipv4Addr::LOCALHOST])]),
            exempt: vec![Ipv4Addr::LOCALHOST],
        }
    }

    /// The next event that is not a connection count.
    async fn next<R: AsyncRead + Unpin>(r: &mut R) -> FromProxy {
        loop {
            match ipc::read::<_, FromProxy>(r).await.unwrap().unwrap().0 {
                FromProxy::Connections { .. } => continue,
                e => return e,
            }
        }
    }

    fn wire(name: &str, len: usize) -> WireCredential {
        WireCredential { name: name.into(), adapter: AdapterType::Bearer, destination: "dest.test".into(), len }
    }

    /// The process answers Hello with the ports it bound, registers a sandbox from a
    /// Register frame, substitutes its credential, streams its log line, answers
    /// Unregister after that line, and ends when the agent's end closes.
    #[tokio::test]
    async fn the_process_serves_what_the_agent_registers() {
        let (agent, process) = tokio::io::duplex(1 << 16);
        let (from_agent, to_agent) = tokio::io::split(process);
        let (mut events, mut commands) = tokio::io::split(agent);
        let running = tokio::spawn(run(from_agent, to_agent));

        let ca = CaKey::generate("test").unwrap();
        ipc::write(&mut commands, &hello(&ca), ca.key_der()).await.unwrap();
        let FromProxy::Ready { ports } = next(&mut events).await else { panic!("not ready") };
        assert_ne!(ports.connect, 0, "the port bound, not the 0 asked for");

        let (port, seen) = testing::destination().await;
        let policy = testing::policy(&format!(r#"[{{"host":"dest.test","port":{port},"adapter":{{"type":"bearer","credential":"svc"}}}}]"#));
        let register = ToProxy::Register {
            ip: Ipv4Addr::LOCALHOST,
            sandbox: SandboxId::generate().to_string(),
            bundle: common::b64::encode(policy.bytes()),
            ceiling: policy.limits.max.into(),
            credentials: vec![wire("svc", 11)],
        };
        ipc::write(&mut commands, &register, b"REAL-SECRET").await.unwrap();
        let FromProxy::Registered { ip: Ipv4Addr::LOCALHOST, sandbox } = next(&mut events).await else { panic!("not registered") };

        let target = format!("dest.test:{port}");
        let connect = (Ipv4Addr::LOCALHOST, ports.connect).into();
        let got = testing::through(connect, &target, &format!("GET / HTTP/1.1\r\nHost: {target}\r\nAuthorization: Bearer clovelly://cred/svc\r\nConnection: close\r\n\r\n"))
            .await
            .unwrap();
        assert!(got.ends_with("ok"), "{got}");
        assert!(seen.lock().unwrap()[0].contains("Bearer REAL-SECRET\r\n"));

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let unregister = ToProxy::Unregister { ip: Ipv4Addr::LOCALHOST, sandbox: sandbox.clone() };
        ipc::write(&mut commands, &unregister, &[]).await.unwrap();
        let FromProxy::Log { line, .. } = next(&mut events).await else { panic!("no log line") };
        assert!(line.contains(r#""credential":"svc""#) && !line.contains("REAL-SECRET"), "{line}");
        assert_eq!(next(&mut events).await, FromProxy::Unregistered { ip: Ipv4Addr::LOCALHOST, sandbox });

        commands.shutdown().await.unwrap();
        assert!(running.await.unwrap().is_ok(), "the process ends when the agent's end closes");
    }

    #[test]
    fn register_frames_split_their_secrets_by_length() {
        let policy = testing::policy(r#"[{"host":"dest.test","port":443,"adapter":{"type":"bearer","credential":"svc"}}]"#);
        let bundle = common::b64::encode(policy.bytes());
        let mut blob = Blob(b"AAAABBB".to_vec().into_boxed_slice());
        let id = SandboxId::generate().to_string();
        let ceiling: common::sandbox::Size = Ceiling::from(policy.limits.max).into();
        let e = parse_register(&id, &bundle, ceiling, &[wire("a", 4), wire("b", 3)], &blob, |_| {}).unwrap();
        assert_eq!(e.sandbox.to_string(), id);
        assert_eq!(e.policy.hash, policy.hash);
        assert_eq!(e.credentials[&"a".parse().unwrap()].secret.expose(), b"AAAA");
        assert_eq!(e.credentials[&"b".parse().unwrap()].secret.expose(), b"BBB");
        for lens in [&[4usize, 4][..], &[4, 2], &[usize::MAX, 1]] {
            let wires: Vec<_> = lens.iter().map(|l| wire("a", *l)).collect();
            assert!(matches!(parse_register(&id, &bundle, ceiling, &wires, &blob, |_| {}), Err(RegisterError::Secrets)), "{lens:?}");
        }
        blob.0[0] = b'\n';
        assert!(matches!(parse_register(&id, &bundle, ceiling, &[wire("a", 4), wire("b", 3)], &blob, |_| {}), Err(RegisterError::Credential(_))));
    }
}
