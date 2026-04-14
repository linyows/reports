# Contributing to Reports

Thank you for your interest in contributing! This guide explains how to get started.

## Getting Started

### Prerequisites

- Zig 0.15.2 or later
- libxml2, libcurl, zlib (included in macOS SDK)
- Xcode 16+ (for macOS app development)

### Build and Test

```bash
# Build
zig build

# Run tests
zig build test

# Format check
zig fmt --check src/

# Run
zig build run -- help
```

## How to Contribute

### Reporting Bugs

Open an [issue](https://github.com/linyows/reports/issues) with:

- Steps to reproduce
- Expected vs actual behavior
- Zig version and OS

### Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b my-feature`)
3. Make your changes
4. Ensure tests pass (`zig build test`)
5. Ensure code is formatted (`zig fmt src/`)
6. Commit your changes
7. Push to your fork and open a Pull Request

### Code Style

- Follow Zig's official style conventions
- Run `zig fmt src/` before committing
- Keep functions focused and small
- Add tests for new functionality

## Project Structure

```
src/           Zig core library and CLI
macos/         SwiftUI macOS application
misc/          Assets (logo, icons)
```

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
