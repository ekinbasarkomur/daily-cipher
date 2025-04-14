# Daily Cipher

Daily Cipher is an Obsidian plugin that securely encrypts and decrypts files in the "Daily" folder of your vault using AES-GCM encryption. It ensures that only encrypted files are committed to GitHub by managing the `.gitignore` file automatically.

## Features

- **Secure Encryption**: Encrypts files in the "Daily" folder using AES-GCM with a password-derived key (PBKDF2, 100,000 iterations).
- **Automatic Git Protection**: Adds `Daily/` to `.gitignore` when decrypting to prevent plaintext commits, and removes it when encrypting to allow secure commits.
- **Simple Interface**: Provides a modal with buttons to encrypt or decrypt all files in the "Daily" folder.

**No Password Storage**: Passwords are input per session and never saved, enhancing security.

## Installation

1. Copy the plugin folder to `.obsidian/plugins/daily-cipher/` in your Obsidian vault.
2. Ensure you have Node.js and TypeScript installed.
3. Run `npm install` and `npm run build` in the plugin folder to compile the TypeScript code.
4. Enable the plugin in Obsidian’s settings under "Community Plugins."

## Usage

1. Ensure a "Daily" folder exists in your vault’s root.
2. Click the lock icon in the ribbon or use the command `Open Daily Cipher modal`.
3. Enter a strong password (e.g., 16+ characters with letters, numbers, symbols).
4. Click **Encrypt Daily Notes** to:
   - Encrypt all files in the "Daily" folder.
   - Remove `Daily/` from `.gitignore`, allowing encrypted files to be committed to GitHub.
5. Click **Decrypt Daily Notes** to:
   - Decrypt all files in the "Daily" folder.
   - Add `Daily/` to `.gitignore`, preventing plaintext files from being committed.
6. Use Git commands (`git add`, `git commit`, `git push`) to manage your repository.

## Important Notes

- **Backup**: Always back up your "Daily" folder before encrypting, as a lost password makes files unrecoverable.
- **Password**: Use a strong, memorable password. The plugin does not store it.
- **Git**: The plugin modifies `.gitignore` but does not execute Git commands. You must manually commit and push changes.
- **File Scope**: Affects all files in the "Daily" folder. To limit to specific types (e.g., `.md`), modify the plugin code.

## Security

- Uses AES-GCM for authenticated encryption, ensuring confidentiality, integrity, and authenticity.
- Derives keys with PBKDF2 (100,000 iterations) for resistance to brute-force attacks.
- Stores only non-sensitive data (IV, salt, ciphertext) in files, never the password or key.
- Adds `Daily/` to `.gitignore` during decryption to prevent accidental plaintext leaks.

## Troubleshooting

- **"Daily folder not found"**: Ensure the "Daily" folder exists in your vault’s root.
- **"Invalid password or corrupted data"**: Verify the password matches the one used for encryption.
- **.gitignore issues**: Check that `.gitignore` is in the vault’s root and writable.

## License

MIT License. See LICENSE for details.