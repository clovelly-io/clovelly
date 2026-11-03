//! `egress-proxy`: the egress proxy as its own process, started by the cell agent
//! ([`egress_proxy::Supervisor`]). Its stdin and stdout are pipes to the agent, which
//! sends its configuration and sandboxes and reads back log lines and acknowledgements
//! ([`egress_proxy::ipc`]); diagnostics go to stderr. It exits when the agent's end of
//! stdin closes.

use std::io;
use std::os::fd::AsFd;
use std::process::ExitCode;

use tokio::net::unix::pipe;

#[tokio::main]
async fn main() -> ExitCode {
    match serve().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("egress-proxy: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Error from setting up the pipes or running the proxy.
#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("stdin and stdout must be pipes from the cell agent: {0}")]
    Pipes(io::Error),
    #[error(transparent)]
    Process(#[from] egress_proxy::process::ProcessError),
}

async fn serve() -> Result<(), Error> {
    // Our own descriptors for the two pipes, read and written without the standard
    // streams' buffers, which would keep copies of the secrets that pass through them.
    let input = io::stdin().as_fd().try_clone_to_owned().and_then(pipe::Receiver::from_owned_fd).map_err(Error::Pipes)?;
    let output = io::stdout().as_fd().try_clone_to_owned().and_then(pipe::Sender::from_owned_fd).map_err(Error::Pipes)?;
    egress_proxy::process::run(input, output).await?;
    Ok(())
}
