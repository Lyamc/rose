#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

/// COVERAGE: Thin entry point; all logic lives in `rose::cli`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn main() -> anyhow::Result<()> {
    // `StartServiceCtrlDispatcher` has to run on the process main thread,
    // before tokio takes that thread.
    if std::env::args().nth(1).as_deref() == Some("service")
        && std::env::args().nth(2).as_deref() == Some("run")
    {
        return rose::cli::run_service();
    }
    async_main()
}

/// COVERAGE: Thin entry point; all logic lives in `rose::cli`.
#[cfg_attr(coverage_nightly, coverage(off))]
#[tokio::main]
async fn async_main() -> anyhow::Result<()> {
    rose::cli::run().await
}
