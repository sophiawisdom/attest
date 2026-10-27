This is i18n-embed-fl 0.9.4 from crates.io (MIT, Copyright Luke Frisken and
contributors) with one change in `src/lib.rs`: the `fl!` macro's named
arguments are emitted in sorted order instead of `HashMap` iteration order.
Without this, builds of `age` 0.11 (which depends on `^0.9`) are not
reproducible. The same fix exists upstream in 0.10.1. See `git log` for the diff
against the pristine crate.
