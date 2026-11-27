/* Fallback when no Qt 6 headers are found at build time: the call still
 * exists, so the Rust side links, but nothing happens. build.rs prints a
 * warning when it uses this. */
void bm_set_window_icon(const char *path)
{
    (void)path;
}
