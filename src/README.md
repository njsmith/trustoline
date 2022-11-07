# What is this?



# How do you use it?

# How is it designed?

# How do you rebuild it?

Building this can be frustrating, because the low-level compiler/runtime
machinery have a bunch of implicit assumptions about the environment they'll run
in, and the facilities it provides for things like `memcpy`, unwinding, etc.
With `#![no_std]` most of this machinery is missing. So we need to replace the
bits that we actually need, and which bits we need can change depending on stuff
like optimization options. For example: we use `panic="abort"`, so we don't
actually need unwinding support, but at lower optimization levels the compiler
might still emit a reference to `__CxxFrameHandler3`, even though we'll never
actually use it at runtime.

Two approaches that are reasonably likely to work:

- Uncomment `compiler-builtins` in `Cargo.toml`, and build normally: `cargo
  build --profile release`.
- Leave `compiler-builtins` commented-out, and build like: `cargo +nightly build
  -Z build-std=core,panic_abort,alloc -Z
  build-std-features=compiler-builtins-mem --target x86_64-pc-windows-msvc
  --profile=release`

I know that the latter worked with "rustc 1.67.0-nightly (09508489e
2022-11-04)".