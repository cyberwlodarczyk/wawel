# Wawel 🏰

## Introduction

This is a file encryption and decryption tool that uses scrypt and ChaCha20-Poly1305 under the hood to provide both confidentiality and integrity. It has not been thoroughly tested or reviewed by a security professional and is intended for educational purposes only. The file size limit has been set to 512MB because the data is encrypted/decrypted in one go.

## Compilation

Make sure you have `libsodium` installed on your machine. You may also have to run `sudo ldconfig` to update the shared library cache (as in my case).

```bash
git clone https://github.com/cyberwlodarczyk/wawel.git
cd wawel
gcc -o wawel wawel.c -lsodium
```

## Usage

Each file is protected by a password that needs to be entered for each operation.

### Encryption

```bash
./wawel data.json
```

### Decryption

```bash
./wawel data.json.wawel
```

## Contributing

If you would like to contribute to the project, feel free to fork the repository and submit a pull request.

## License

This project is licensed under the [MIT License](https://opensource.org/license/mit/) - see the [LICENSE](LICENSE) file for details.
