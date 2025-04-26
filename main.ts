import { App, Editor, MarkdownView, Modal, Notice, Plugin, PluginSettingTab, Setting, TFile, TFolder, TAbstractFile } from 'obsidian';

interface DailyCipherSettings {
    storePassword: boolean;
    encryptionKey: string;
}

const DEFAULT_SETTINGS: DailyCipherSettings = {
    storePassword: false,
    encryptionKey: ''
}

export default class DailyCipher extends Plugin {
    settings: DailyCipherSettings;

    async onload() {
        await this.loadSettings();

        // Ribbon icon to open the encryption/decryption modal
        const ribbonIconEl = this.addRibbonIcon('lock', 'Daily Cipher', (evt: MouseEvent) => {
            new CryptoModal(this.app, this).open();
        });
        ribbonIconEl.addClass('daily-cipher-ribbon-class');

        // Status bar item
        const statusBarItemEl = this.addStatusBarItem();
        statusBarItemEl.setText('Daily Cipher Active');

        // Command to open the modal
        this.addCommand({
            id: 'open-crypto-modal',
            name: 'Open Daily Cipher modal',
            callback: () => {
                new CryptoModal(this.app, this).open();
            }
        });

        // Editor command (unchanged)
        this.addCommand({
            id: 'sample-editor-command',
            name: 'Sample editor command',
            editorCallback: (editor: Editor, view: MarkdownView) => {
                console.log(editor.getSelection());
                editor.replaceSelection('Sample Editor Command');
            }
        });

        // Complex command (unchanged)
        this.addCommand({
            id: 'open-sample-modal-complex',
            name: 'Open Daily Cipher modal (complex)',
            checkCallback: (checking: boolean) => {
                const markdownView = this.app.workspace.getActiveViewOfType(MarkdownView);
                if (markdownView) {
                    if (!checking) {
                        new CryptoModal(this.app, this).open();
                    }
                    return true;
                }
            }
        });

        // Settings tab
        this.addSettingTab(new DailyCipherSettingTab(this.app, this));

        // Global DOM event (unchanged)
        this.registerDomEvent(document, 'click', (evt: MouseEvent) => {
            console.log('click', evt);
        });

        // Interval (unchanged)
        this.registerInterval(window.setInterval(() => console.log('setInterval'), 5 * 60 * 1000));
    }

    onunload() {
        // Cleanup if needed
    }

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
    }

    async saveSettings() {
        await this.saveData(this.settings);
    }
}

// Modal for encryption/decryption
class CryptoModal extends Modal {
    plugin: DailyCipher;
    private password: string = '';

    constructor(app: App, plugin: DailyCipher) {
        super(app);
        this.plugin = plugin;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.createEl('h2', { text: 'Daily Cipher: Encrypt/Decrypt Notes' });
        
        // Password input field
        new Setting(contentEl)
            .setName('Password')
            .setDesc('Enter your encryption password')
            .addText(text => text
                .setPlaceholder('Enter password')
                .setValue(this.plugin.settings.storePassword ? this.plugin.settings.encryptionKey : '')
                .onChange(async (value) => {
                    this.password = value;
                    if (this.plugin.settings.storePassword) {
                        this.plugin.settings.encryptionKey = value;
                        await this.plugin.saveSettings();
                    }
                }));

        // Encrypt button
        new Setting(contentEl)
            .addButton(button => button
                .setButtonText('Encrypt Daily Notes')
                .setCta()
                .onClick(async () => {
                    try {
                        if (!this.password) {
                            new Notice('Please enter a password');
                            return;
                        }
                        await this.encryptFiles(this.password);
                        new Notice('Encryption completed successfully!');
                    } catch (e) {
                        new Notice(`Encryption failed: ${e.message}`);
                    }
                }))
            .addButton(button => button
                .setButtonText('Decrypt Daily Notes')
                .setCta()
                .onClick(async () => {
                    try {
                        if (!this.password) {
                            new Notice('Please enter a password');
                            return;
                        }
                        await this.decryptFiles(this.password);
                        new Notice('Decryption completed successfully!');
                    } catch (e) {
                        new Notice(`Decryption failed: ${e.message}`);
                    }
                }));
    }

    // Recursively collect all files from a folder and its subdirectories
    private collectFiles(folder: TFolder): TFile[] {
        let files: TFile[] = [];
        for (const child of folder.children) {
            if (child instanceof TFile) {
                files.push(child);
            } else if (child instanceof TFolder) {
                files = files.concat(this.collectFiles(child));
            }
        }
        return files;
    }

    // Check if a file is an image or video based on extension
    private isMedia(file: TFile): boolean {
        const mediaExtensions = [
            'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', // Images
            'mp4', 'mov', 'avi', 'mkv', 'webm' // Videos
        ];
        const extension = file.extension.toLowerCase();
        return mediaExtensions.includes(extension);
    }

    private isEncrypted(content: string): boolean {
        try {
            const parsed = JSON.parse(content);
            // Check if the parsed object has the expected structure for encrypted data
            return parsed.iv && parsed.salt && parsed.ciphertext && 
                   typeof parsed.iv === 'string' && 
                   typeof parsed.salt === 'string' && 
                   typeof parsed.ciphertext === 'string';
        } catch (e) {
            // If parsing fails, it's not an encrypted file
            return false;
        }
    }

    // Add these new helper functions
    private separateFrontMatter(content: string): { frontMatter: string | null, mainContent: string } {
        const frontMatterRegex = /^---([\s\S]*?)---\n([\s\S]*)$/;
        const match = content.match(frontMatterRegex);
        
        if (match) {
            return {
                frontMatter: `---${match[1]}---\n`,
                mainContent: match[2]
            };
        }
        
        return {
            frontMatter: null,
            mainContent: content
        };
    }

    private combineFrontMatterAndContent(frontMatter: string | null, content: string): string {
        if (frontMatter) {
            return `${frontMatter}${content}`;
        }
        return content;
    }

    async encryptFiles(password: string) {
        if (!password) {
            throw new Error('Please provide a password!');
        }

        const dailyFolder = this.app.vault.getAbstractFileByPath('Journal/Daily');
        if (!(dailyFolder instanceof TFolder)) {
            throw new Error('Daily folder not found!');
        }

        const files = this.collectFiles(dailyFolder);
        if (files.length === 0) {
            throw new Error('No files found in Daily folder or its subdirectories!');
        }

        let encryptedCount = 0;
        for (const file of files) {
            try {
                if (this.isMedia(file)) {
                    new Notice(`Skipped ${file.path}: media file`);
                    continue;
                }
                const content = await this.app.vault.read(file);
                
                // Skip if already encrypted
                if (this.isEncrypted(content)) {
                    new Notice(`Skipped ${file.path}: already encrypted`);
                    continue;
                }

                // Separate frontmatter and content
                const { frontMatter, mainContent } = this.separateFrontMatter(content);
                
                // Only encrypt the main content
                const encryptedData = await this.encryptContent(mainContent, password);
                const encodedData = this.encodeEncryptedData(encryptedData);
                
                // Combine frontmatter with encrypted content
                const finalContent = this.combineFrontMatterAndContent(frontMatter, encodedData);
                
                await this.app.vault.modify(file, finalContent);
                encryptedCount++;
            } catch (e) {
                new Notice(`Failed to encrypt ${file.path}: ${e.message}`);
                continue;
            }
        }

        if (encryptedCount === 0) {
            new Notice('No files were encrypted: all files were media or failed.');
        }
    }

    async decryptFiles(password: string) {
        if (!password) {
            throw new Error('Please provide a password!');
        }

        const dailyFolder = this.app.vault.getAbstractFileByPath('Journal/Daily');
        if (!(dailyFolder instanceof TFolder)) {
            throw new Error('Daily folder not found!');
        }

        const files = this.collectFiles(dailyFolder);
        if (files.length === 0) {
            throw new Error('No files found in Daily folder or its subdirectories!');
        }

        for (const file of files) {
            try {
                const content = await this.app.vault.read(file);
                
                // Separate frontmatter and content
                const { frontMatter, mainContent } = this.separateFrontMatter(content);
                
                // Only decrypt the main content
                const encryptedData = this.decodeEncryptedData(mainContent);
                const decryptedContent = await this.decryptContent(encryptedData, password);
                
                // Combine frontmatter with decrypted content
                const finalContent = this.combineFrontMatterAndContent(frontMatter, decryptedContent);
                
                await this.app.vault.modify(file, finalContent);
            } catch (e) {
                new Notice(`Failed to decrypt ${file.path}: ${e.message}`);
                continue;
            }
        }
    }

    // Derive a key from password using PBKDF2
    async deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
        const passwordBuffer = new TextEncoder().encode(password);
        const baseKey = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            'PBKDF2',
            false,
            ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    // Encrypt content with AES-GCM
    async encryptContent(content: string, password: string): Promise<{ iv: Uint8Array, salt: Uint8Array, ciphertext: ArrayBuffer }> {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await this.deriveKey(password, salt);
        const encodedContent = new TextEncoder().encode(content);
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encodedContent
        );
        return { iv, salt, ciphertext };
    }

    // Decrypt content with AES-GCM
    async decryptContent(data: { iv: Uint8Array, salt: Uint8Array, ciphertext: ArrayBuffer }, password: string): Promise<string> {
        try {
            const key = await this.deriveKey(password, data.salt);
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: data.iv },
                key,
                data.ciphertext
            );
            return new TextDecoder().decode(decrypted);
        } catch (e) {
            throw new Error('Invalid password or corrupted data');
        }
    }

    // Encode encrypted data to string (base64)
    encodeEncryptedData(data: { iv: Uint8Array, salt: Uint8Array, ciphertext: ArrayBuffer }): string {
        const ivBase64 = btoa(String.fromCharCode(...data.iv));
        const saltBase64 = btoa(String.fromCharCode(...data.salt));
        const ciphertextBase64 = btoa(String.fromCharCode(...new Uint8Array(data.ciphertext)));
        return JSON.stringify({ iv: ivBase64, salt: saltBase64, ciphertext: ciphertextBase64 });
    }

    // Decode encrypted data from string
    decodeEncryptedData(encoded: string): { iv: Uint8Array, salt: Uint8Array, ciphertext: ArrayBuffer } {
        try {
            const parsed = JSON.parse(encoded);
            const iv = new Uint8Array(atob(parsed.iv).split('').map(c => c.charCodeAt(0)));
            const salt = new Uint8Array(atob(parsed.salt).split('').map(c => c.charCodeAt(0)));
            const ciphertext = new Uint8Array(atob(parsed.ciphertext).split('').map(c => c.charCodeAt(0))).buffer;
            return { iv, salt, ciphertext };
        } catch (e) {
            throw new Error('Invalid encrypted data format');
        }
    }

    onClose() {
        const { contentEl } = this;
        contentEl.empty();
    }
}

class DailyCipherSettingTab extends PluginSettingTab {
    plugin: DailyCipher;

    constructor(app: App, plugin: DailyCipher) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display(): void {
        const { containerEl } = this;
        containerEl.empty();

        containerEl.createEl('h2', { text: 'Daily Cipher Settings' });

        new Setting(containerEl)
            .setName('Store Password')
            .setDesc('WARNING: Storing passwords is not recommended for security. Only enable if you understand the risks.')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.storePassword)
                .onChange(async (value) => {
                    this.plugin.settings.storePassword = value;
                    if (!value) {
                        // Clear stored password when disabling storage
                        this.plugin.settings.encryptionKey = '';
                    }
                    await this.plugin.saveSettings();
                    // Refresh the settings display
                    this.display();
                }));

        // Only show password field if storage is enabled
        if (this.plugin.settings.storePassword) {
            new Setting(containerEl)
                .setName('Encryption Key')
                .setDesc('Your encryption key will be stored in settings')
                .addText(text => text
                    .setPlaceholder('Enter encryption key')
                    .setValue(this.plugin.settings.encryptionKey)
                    .onChange(async (value) => {
                        this.plugin.settings.encryptionKey = value;
                        await this.plugin.saveSettings();
                    }));
        } else {
            containerEl.createEl('p', { 
                text: 'Password storage is disabled. You will need to enter the password each time you want to encrypt or decrypt notes.' 
            });
        }

        // Add security notice
        containerEl.createEl('h3', { text: 'Security Notice' });
        const ul = containerEl.createEl('ul');
        ul.createEl('li', { 
            text: 'Storing passwords in settings makes them accessible to other plugins and stored in plain text' 
        });
        ul.createEl('li', { 
            text: 'For maximum security, keep password storage disabled and enter the password each time' 
        });
    }
}