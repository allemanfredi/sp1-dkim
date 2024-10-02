# sp1-dkim

This repository contains an SP1 program that verifies DKIM signatures.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Building the Program](#building-the-program)
  - [Running the Script](#running-the-script)
- [Example](#example)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Prerequisites

Before you begin, ensure you have the following installed:

- **Rust Programming Language**: Install Rust by following the instructions [here](https://www.rust-lang.org/tools/install).
- **SP1**: Install SP1 by following the [official installation guide](https://docs.succinct.xyz/getting-started/install.html).

## Installation

Clone the repository and navigate into it:

```bash
git clone https://github.com/allemanfredi/sp1-dkim.git
cd sp1-dkim
```

## Usage

### Building the Program

Navigate to the `program` directory and build the SP1 proof:

```bash
cd program
cargo prove build
```

### Running the Script

Navigate to the `script` directory and execute the script:

```bash
cd ../script
RUST_LOG=info cargo run --release -- --execute \
    <from_domain> \
    <email_path> \
```

If you want to generate the proof, replace `execute` with `prove`

**Parameters:**

- `<from_domain>`: The domain where the mail comes from.
- `<email_path>`: The path to the file containing the email.

## Example

Here's an example command:

```bash
RUST_LOG=info cargo run --release -- --execute \
    example.com \
    ./email.eml
```

## Disclaimer

**This code is not audited. Use it at your own risk.** The repository owners and contributors are not liable for any damages or issues that may arise from using this software.

## Contributing

Contributions are welcome! If you have suggestions or find issues, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).
