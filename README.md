# Locker - Secure Password Manager

A secure command-line password manager written in Rust. Locker uses industry-standard encryption (AES-256-GCM) and key derivation (Argon2) to safely store your passwords.

## Features

- Secure password storage using AES-256-GCM encryption
- Strong master key protection using Argon2 key derivation
- Automatic password generation
- Clipboard integration for secure password copying
- Session management with automatic timeout
- Brute force protection
- Password strength validation

## Installation

```bash
cargo install --path .
```

## Usage

### First Time Setup
The first time you run any command, you'll be prompted to create a master password. Choose a strong password as this protects all your other passwords.

### Commands

```bash
# Generate a new password
locker generate [length] [--app name]  # Generates a secure password, optionally saving it for an app

# Add a password
locker add <app>  # Stores a password for an app (prompts for password)

# Change a password
locker change <app>  # Changes a stored password (prompts for new password)

# Get a password
locker get <app>  # Retrieves a password (copies to clipboard)

# List all stored passwords
locker list  # Shows all stored app names

# Delete a password
locker delete <app>  # Removes a stored password
```

### Examples

```bash
# Generate a 20-character password and save it for GitHub
locker generate 20 github

# Add a password manually
locker add email
# You will be prompted to enter the password securely

# Change an existing password
locker change email
# You will be prompted to enter the new password securely

# Retrieve a password (copies to clipboard)
locker get email

# List all stored passwords
locker list

# Delete a password
locker delete email
```

## Security Features

- Passwords are encrypted using AES-256-GCM
- Master key is derived using Argon2, a memory-hard key derivation function
- Passwords are never displayed in plain text, only copied to clipboard
- Session timeout after 15 minutes of inactivity
- Brute force protection with attempt limiting
- Strong password requirements enforcement
- Secure memory handling with automatic wiping
- Interactive password entry to prevent exposure in shell history

## Best Practices

1. Use a strong master password
2. Use generated passwords when possible
3. Use unique passwords for each service
4. Regularly backup your password store
5. Keep your master password safe and memorable

## Development

Built with Rust using the following key crates:
- `aes-gcm` for encryption
- `argon2` for key derivation
- `clap` for CLI interface
- `zeroize` for secure memory wiping

## License

MIT License
