import { App, Editor, MarkdownView, Modal, Notice, Plugin, PluginSettingTab, Setting, TFile, TFolder } from 'obsidian';

interface DailyCipherSettings {
    mySetting: string;
}

const DEFAULT_SETTINGS: DailyCipherSettings = {
    mySetting: 'default'
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
        this.addSettingTab(new SampleSettingTab(this.app, this));

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

    // Add Daily/ to .gitignore
    async addToGitignore() {
        const gitignorePath = '.gitignore';
        const dailyEntry = 'Daily/';
        let content = '';

        // Check if .gitignore exists
        const gitignoreFile = this.app.vault.getAbstractFileByPath(gitignorePath);
        if (gitignoreFile instanceof TFile) {
            content = await this.app.vault.read(gitignoreFile);
        }

        // Add Daily/ if not already present
        if (!content.split('\n').includes(dailyEntry)) {
            content = content ? `${content.trim()}\n${dailyEntry}\n` : `${dailyEntry}\n`;
            if (gitignoreFile instanceof TFile) {
                await this.app.vault.modify(gitignoreFile, content);
            } else {
                await this.app.vault.create(gitignorePath, content);
            }
            new Notice('Added Daily/ to .gitignore');
        }
    }

    // Remove Daily/ from .gitignore
    async removeFromGitignore() {
        const gitignorePath = '.gitignore';
        const dailyEntry = 'Daily/';
        const gitignoreFile = this.app.vault.getAbstractFileByPath(gitignorePath);

        if (gitignoreFile instanceof TFile) {
            let content = await this.app.vault.read(gitignoreFile);
            const lines = content.split('\n');
            const updatedLines = lines.filter(line => line.trim() !== dailyEntry);
            const updatedContent = updatedLines.join('\n').trim() + '\n';

            if (updatedLines.length < lines.length) {
                await this.app.vault.modify(gitignoreFile, updatedContent);
                new Notice('Removed Daily/ from .gitignore');
            }
        }
    }
}

// Modal for encryption/decryption
class CryptoModal extends Modal {
    plugin: DailyCipher;

    constructor(app: App, plugin: DailyCipher) {
        super(app);
        this.plugin = plugin;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.createEl('h2', { text: 'Daily Cipher: Encrypt/Decrypt Notes' });

        // Input for password (not stored in state)
        let passwordInput: HTMLInputElement;
        new Setting(contentEl)
            .setName('Password')
            .setDesc('Enter a strong password for encryption/decryption')
            .addText(text => {
                passwordInput = text.inputEl;
                text.setPlaceholder('Enter password').setValue('');
            });

        // Encrypt button
        new Setting(contentEl)
            .addButton(button => button
                .setButtonText('Encrypt Daily Notes')
                .setCta()
                .onClick(async () => {
                    try {
                        const password = passwordInput.value;
                        await this.encryptFiles(password);
                        //await this.plugin.removeFromGitignore();
                        new Notice('Encryption completed successfully!');
                    } catch (e) {
                        new Notice(`Encryption failed: ${e.message}`);
                    }
                }));

        // Decrypt button
        new Setting(contentEl)
            .addButton(button => button
                .setButtonText('Decrypt Daily Notes')
                .setCta()
                .onClick(async () => {
                    try {
                        const password = passwordInput.value;
                        await this.decryptFiles(password);
                        //await this.plugin.addToGitignore();
                        new Notice('Decryption completed successfully!');
                    } catch (e) {
                        new Notice(`Decryption failed: ${e.message}`);
                    }
                }));
    }

    async encryptFiles(password: string) {
        if (!password) {
            throw new Error('Please provide a password!');
        }

        const dailyFolder = this.app.vault.getAbstractFileByPath('Daily');
        if (!(dailyFolder instanceof TFolder)) {
            throw new Error('Daily folder not found!');
        }

        const files = dailyFolder.children.filter(file => file instanceof TFile) as TFile[];
        for (const file of files) {
            const content = await this.app.vault.read(file);
            const encryptedData = await this.encryptContent(content, password);
            const encodedData = this.encodeEncryptedData(encryptedData);
            await this.app.vault.modify(file, encodedData);
        }
    }

    async decryptFiles(password: string) {
        if (!password) {
            throw new Error('Please provide a password!');
        }

        const dailyFolder = this.app.vault.getAbstractFileByPath('Daily');
        if (!(dailyFolder instanceof TFolder)) {
            throw new Error('Daily folder not found!');
        }

        const files = dailyFolder.children.filter(file => file instanceof TFile) as TFile[];
        for (const file of files) {
            const encodedData = await this.app.vault.read(file);
            const encryptedData = this.decodeEncryptedData(encodedData);
            const decryptedContent = await this.decryptContent(encryptedData, password);
            await this.app.vault.modify(file, decryptedContent);
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

class SampleSettingTab extends PluginSettingTab {
    plugin: DailyCipher;

    constructor(app: App, plugin: DailyCipher) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display(): void {
        const { containerEl } = this;
        containerEl.empty();

        new Setting(containerEl)
            .setName('Setting #1')
            .setDesc('It\'s a secret')
            .addText(text => text
                .setPlaceholder('Enter your secret')
                .setValue(this.plugin.settings.mySetting)
                .onChange(async (value) => {
                    this.plugin.settings.mySetting = value;
                    await this.plugin.saveSettings();
                }));
    }
}