use std::{path::PathBuf, process::exit, sync::Arc};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1).peekable();
    let init = args.next_if(|a| a == "init").is_some();
    let path = PathBuf::from(args.next().unwrap_or_else(|| "./dev-idp.toml".into()));

    if init {
        if let Err(e) = dev_idp::config::initialize_config_file(&path) {
            eprintln!("{e}");
            exit(1);
        }
        println!("key material ready in {}", path.display());
        return;
    }

    let state = match dev_idp::config::load_and_ensure_key_material(&path)
        .and_then(dev_idp::AppState::new)
    {
        Ok(state) => Arc::new(state),
        Err(e) => {
            eprintln!("{e}");
            exit(1);
        }
    };
    let bind = state.cfg.server.bind.clone();
    let issuer = state.cfg.server.issuer.clone();
    let router = dev_idp::build_router(state);
    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind {bind}: {e}");
            exit(1);
        }
    };
    println!(
        "{}{}, issuer {issuer}",
        dev_idp::STARTUP_LINE_PREFIX,
        listener.local_addr().unwrap()
    );
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .unwrap();
}
