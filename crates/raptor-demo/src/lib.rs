#[cfg(target_os = "linux")]
pub mod await_tracker;

#[cfg(not(target_os = "linux"))]
pub mod await_tracker {
    #[macro_export]
    macro_rules! tracked_await {
        ($expr:expr, $labl:literal) => {{$expr}};
        ($expr:expr) => {{$expr}};
    }
    pub fn print_report() {}
}
