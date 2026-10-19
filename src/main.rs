use threshold_ecdsa::api::{KeyService, router};

#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("bind 127.0.0.1:3000");
    println!("listening on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, router(KeyService::default()))
        .await
        .unwrap();
}
