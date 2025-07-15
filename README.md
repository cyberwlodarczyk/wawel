# Wawel 🏰

## Introduction

Wawel is a file encryption and decryption tool for Linux that uses Argon2id and ChaCha20-Poly1305 under the hood to provide both confidentiality and integrity. It encrypts data in small chunks and can handle files of any size. **It has not been thoroughly tested or reviewed by a security professional and is intended for educational purposes only.**

## Installation

### Download

You can download the latest binary from the [Releases](https://github.com/cyberwlodarczyk/wawel/releases) section.

### Compile

Make sure you have `libsodium` installed on your machine. You may also have to run `sudo ldconfig` to update the shared library cache.

```bash
git clone https://github.com/cyberwlodarczyk/wawel.git
cd wawel
gcc -o wawel wawel.c -lsodium
```

## Usage

Each file is protected by a password that needs to be entered before encryption or decryption. The decision about which action to take is determined by the absence or presence of `.wawel` extension. Then a new file is created with that suffix either added or removed.

### Encryption

```bash
wawel data.json
```

### Decryption

```bash
wawel data.json.wawel
```

## Contributing

If you would like to contribute to the project, feel free to fork the repository and submit a pull request.

## License

This project is licensed under the [MIT License](https://opensource.org/license/mit/) - see the [LICENSE](LICENSE) file for details.
