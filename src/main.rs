use writ_agent::cli;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    cli::commands::run().await;
}
