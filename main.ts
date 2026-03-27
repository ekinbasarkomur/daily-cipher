import { App, Editor, MarkdownView, Modal, Notice, Plugin, PluginSettingTab, Setting, TFile, TFolder } from 'obsidian';

interface DailyCipherSettings {
    /** Vault path to the folder of daily notes (no leading/trailing slashes), e.g. Daily or Journey/Daily */
    dailyNotesFolder: string;
    storePassword: boolean;
    encryptionKey: string;
}

const DEFAULT_SETTINGS: DailyCipherSettings = {
    dailyNotesFolder: 'Daily',
    storePassword: false,
    encryptionKey: ''
};

/** Normalize user input: trim, strip leading/trailing slashes, collapse separators. Empty → Daily. */
function normalizeDailyNotesFolderPath(raw: string): string {
    let s = raw.trim().replace(/\\/g, '/');
    s = s.replace(/^\/+/, '').replace(/\/+$/, '');
    s = s.replace(/\/+/g, '/');
    return s.length > 0 ? s : 'Daily';
}

function escapeRegex(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Only `{dailyNotesFolder}/YYYY-MM-DD.md` */
function isTargetDailyNotePath(vaultPath: string, dailyFolder: string): boolean {
    const f = normalizeDailyNotesFolderPath(dailyFolder);
    const re = new RegExp(`^${escapeRegex(f)}/\\d{4}-\\d{2}-\\d{2}\\.md$`);
    return re.test(vaultPath);
}

function listTargetDailyFiles(dailyFolder: TFolder, folderSetting: string): TFile[] {
    const out: TFile[] = [];
    for (const child of dailyFolder.children) {
        if (child instanceof TFile && isTargetDailyNotePath(child.path, folderSetting)) {
            out.push(child);
        }
    }
    return out;
}

/**
 * Finds `## Daily` and splits: prefix (through header line), body (until next `## ` line or EOF), suffix (rest).
 */
function parseDailySection(content: string): { prefix: string; dailyBody: string; suffix: string } | null {
    const lines = content.split(/\r?\n/);
    let dailyIdx = -1;
    for (let i = 0; i < lines.length; i++) {
        if (/^## Daily\s*$/.test(lines[i])) {
            dailyIdx = i;
            break;
        }
    }
    if (dailyIdx === -1) return null;

    let endIdx = lines.length;
    for (let j = dailyIdx + 1; j < lines.length; j++) {
        if (/^## /.test(lines[j])) {
            endIdx = j;
            break;
        }
    }

    const prefix = lines.slice(0, dailyIdx + 1).join('\n');
    const dailyBody = lines.slice(dailyIdx + 1, endIdx).join('\n');
    const suffix = endIdx < lines.length ? '\n' + lines.slice(endIdx).join('\n') : '';

    return { prefix, dailyBody, suffix };
}

function replaceDailySectionBody(content: string, newDailyBody: string): string | null {
    const parsed = parseDailySection(content);
    if (!parsed) return null;
    return parsed.prefix + '\n' + newDailyBody + parsed.suffix;
}

function isDailyBodyEmptyOrPlaceholder(body: string): boolean {
    const trimmed = body.trim();
    if (trimmed === '') return true;
    const lines = trimmed.split(/\r?\n/);
    for (const line of lines) {
        const t = line.trim();
        if (t === '') continue;
        if (/^<!--[\s\S]*?-->$/.test(t)) continue;
        if (/^%%[\s\S]*%%$/.test(t)) continue;
        return false;
    }
    return true;
}

/** Body is wrapped as `[<json blob from encodeEncryptedData>]`. */
function isDailyBodyBracketCipher(body: string): boolean {
    const t = body.trim();
    return t.startsWith('[') && t.endsWith(']');
}

function getBracketPayloadFromDailyBody(body: string): string | null {
    const t = body.trim();
    if (!t.startsWith('[') || !t.endsWith(']')) return null;
    return t.slice(1, -1);
}

export default class DailyCipher extends Plugin {
    settings: DailyCipherSettings;

    async onload() {
        await this.loadSettings();

        const ribbonIconEl = this.addRibbonIcon('lock', 'Daily Cipher', () => {
            new CryptoModal(this.app, this).open();
        });
        ribbonIconEl.addClass('daily-cipher-ribbon-class');

        const statusBarItemEl = this.addStatusBarItem();
        statusBarItemEl.setText('Daily Cipher Active');

        this.addCommand({
            id: 'open-crypto-modal',
            name: 'Open Daily Cipher modal',
            callback: () => {
                new CryptoModal(this.app, this).open();
            }
        });

        this.addCommand({
            id: 'encrypt-current-file',
            name: 'Encrypt ## Daily section (current file)',
            editorCallback: async (_editor: Editor, view: MarkdownView) => {
                const file = view.file;
                if (!file) {
                    new Notice('No file is currently open');
                    return;
                }
                new CryptoModal(this.app, this, file).open();
            }
        });

        this.addCommand({
            id: 'decrypt-current-file',
            name: 'Decrypt ## Daily section (current file)',
            editorCallback: async (_editor: Editor, view: MarkdownView) => {
                const file = view.file;
                if (!file) {
                    new Notice('No file is currently open');
                    return;
                }
                new CryptoModal(this.app, this, file).open();
            }
        });

        this.addSettingTab(new DailyCipherSettingTab(this.app, this));
    }

    onunload() {}

    async loadSettings() {
        const data = await this.loadData();
        this.settings = Object.assign({}, DEFAULT_SETTINGS, data);
        if (typeof this.settings.dailyNotesFolder === 'string') {
            this.settings.dailyNotesFolder = normalizeDailyNotesFolderPath(this.settings.dailyNotesFolder);
        } else {
            this.settings.dailyNotesFolder = DEFAULT_SETTINGS.dailyNotesFolder;
        }
    }

    async saveSettings() {
        await this.saveData(this.settings);
    }
}

class CryptoModal extends Modal {
    plugin: DailyCipher;
    private password: string = '';
    private targetFile: TFile | null;

    constructor(app: App, plugin: DailyCipher, targetFile: TFile | null = null) {
        super(app);
        this.plugin = plugin;
        this.targetFile = targetFile;
    }

    private folderPath(): string {
        return normalizeDailyNotesFolderPath(this.plugin.settings.dailyNotesFolder);
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        const fp = this.folderPath();
        contentEl.createEl('h2', { text: 'Daily Cipher: Encrypt/Decrypt ## Daily' });

        new Setting(contentEl)
            .setName('Password')
            .setDesc('Enter your encryption password')
            .addText(text => {
                const input = text
                    .setPlaceholder('Enter password')
                    .setValue(this.plugin.settings.storePassword ? this.plugin.settings.encryptionKey : '')
                    .onChange(async (value: string) => {
                        this.password = value;
                        if (this.plugin.settings.storePassword) {
                            this.plugin.settings.encryptionKey = value;
                            await this.plugin.saveSettings();
                        }
                    });
                input.inputEl.type = 'password';
                return input;
            });

        const activeView = this.app.workspace.getActiveViewOfType(MarkdownView);
        const currentFile = this.targetFile ?? activeView?.file;

        if (currentFile) {
            contentEl.createEl('h3', { text: 'Current file' });
            new Setting(contentEl)
                .setName('File')
                .setDesc(
                    `${currentFile.path} — only ${fp}/YYYY-MM-DD.md and only the ## Daily section body are changed (format: [blob]).`
                )
                .addButton(button => button
                    .setButtonText('Encrypt ## Daily')
                    .setCta()
                    .onClick(async () => {
                        try {
                            if (!this.password) {
                                new Notice('Please enter a password');
                                return;
                            }
                            await this.encryptSingleFile(currentFile, this.password);
                        } catch (e) {
                            const msg = e instanceof Error ? e.message : String(e);
                            new Notice(`Encryption failed: ${msg}`);
                        }
                    }))
                .addButton(button => button
                    .setButtonText('Decrypt ## Daily')
                    .setCta()
                    .onClick(async () => {
                        try {
                            if (!this.password) {
                                new Notice('Please enter a password');
                                return;
                            }
                            await this.decryptSingleFile(currentFile, this.password);
                        } catch (e) {
                            const msg = e instanceof Error ? e.message : String(e);
                            new Notice(`Decryption failed: ${msg}`);
                        }
                    }));
        }

        contentEl.createEl('h3', { text: `All notes in ${fp}/` });
        new Setting(contentEl)
            .setName('Batch')
            .setDesc(
                `Encrypt or decrypt the ## Daily section in every ${fp}/YYYY-MM-DD.md file (no other paths or sections).`
            )
            .addButton(button => button
                .setButtonText('Encrypt all')
                .setCta()
                .onClick(async () => {
                    try {
                        if (!this.password) {
                            new Notice('Please enter a password');
                            return;
                        }
                        await this.encryptFiles(this.password);
                        new Notice('Batch encrypt finished.');
                    } catch (e) {
                        const msg = e instanceof Error ? e.message : String(e);
                        new Notice(`Encryption failed: ${msg}`);
                    }
                }))
            .addButton(button => button
                .setButtonText('Decrypt all')
                .setCta()
                .onClick(async () => {
                    try {
                        if (!this.password) {
                            new Notice('Please enter a password');
                            return;
                        }
                        await this.decryptFiles(this.password);
                        new Notice('Batch decrypt finished.');
                    } catch (e) {
                        const msg = e instanceof Error ? e.message : String(e);
                        new Notice(`Decryption failed: ${msg}`);
                    }
                }));
    }

    async encryptFiles(password: string) {
        if (!password) {
            throw new Error('Please provide a password!');
        }

        const folderPath = this.folderPath();
        const dailyFolder = this.app.vault.getAbstractFileByPath(folderPath);
        if (!(dailyFolder instanceof TFolder)) {
            throw new Error(`Daily folder not found: ${folderPath}`);
        }

        const files = listTargetDailyFiles(dailyFolder, this.plugin.settings.dailyNotesFolder);
        if (files.length === 0) {
            throw new Error(`No matching files in ${folderPath} (expected YYYY-MM-DD.md).`);
        }

        for (const file of files) {
            try {
                const content = await this.app.vault.read(file);
                const parsed = parseDailySection(content);
                if (!parsed) continue;

                if (isDailyBodyBracketCipher(parsed.dailyBody)) {
                    continue;
                }
                if (isDailyBodyEmptyOrPlaceholder(parsed.dailyBody)) {
                    continue;
                }

                const encryptedData = await this.encryptContent(parsed.dailyBody, password);
                const encodedData = this.encodeEncryptedData(encryptedData);
                const newBody = `[${encodedData}]`;
                const finalContent = replaceDailySectionBody(content, newBody);
                if (finalContent === null) continue;

                await this.app.vault.modify(file, finalContent);
            } catch (e) {
                const msg = e instanceof Error ? e.message : String(e);
                new Notice(`Failed to encrypt ${file.path}: ${msg}`);
            }
        }
    }

    async decryptFiles(password: string) {
        if (!password) {
            throw new Error('Please provide a password!');
        }

        const folderPath = this.folderPath();
        const dailyFolder = this.app.vault.getAbstractFileByPath(folderPath);
        if (!(dailyFolder instanceof TFolder)) {
            throw new Error(`Daily folder not found: ${folderPath}`);
        }

        const files = listTargetDailyFiles(dailyFolder, this.plugin.settings.dailyNotesFolder);
        if (files.length === 0) {
            throw new Error(`No matching files in ${folderPath} (expected YYYY-MM-DD.md).`);
        }

        for (const file of files) {
            try {
                const content = await this.app.vault.read(file);
                const parsed = parseDailySection(content);
                if (!parsed) continue;

                const payload = getBracketPayloadFromDailyBody(parsed.dailyBody);
                if (payload === null) continue;

                const encryptedData = this.decodeEncryptedData(payload);
                const decryptedBody = await this.decryptContent(encryptedData, password);
                const finalContent = replaceDailySectionBody(content, decryptedBody);
                if (finalContent === null) continue;

                await this.app.vault.modify(file, finalContent);
            } catch (e) {
                const msg = e instanceof Error ? e.message : String(e);
                new Notice(`Failed to decrypt ${file.path}: ${msg}`);
            }
        }
    }

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
                salt: salt as BufferSource,
                iterations: 100000,
                hash: 'SHA-256'
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async encryptContent(content: string, password: string): Promise<{ iv: Uint8Array; salt: Uint8Array; ciphertext: ArrayBuffer }> {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await this.deriveKey(password, salt);
        const encodedContent = new TextEncoder().encode(content);
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv as BufferSource },
            key,
            encodedContent
        );
        return { iv, salt, ciphertext };
    }

    async decryptContent(data: { iv: Uint8Array; salt: Uint8Array; ciphertext: ArrayBuffer }, password: string): Promise<string> {
        try {
            const key = await this.deriveKey(password, data.salt);
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: data.iv as BufferSource },
                key,
                data.ciphertext
            );
            return new TextDecoder().decode(decrypted);
        } catch {
            throw new Error('Invalid password or corrupted data');
        }
    }

    encodeEncryptedData(data: { iv: Uint8Array; salt: Uint8Array; ciphertext: ArrayBuffer }): string {
        const ivBase64 = btoa(String.fromCharCode(...data.iv));
        const saltBase64 = btoa(String.fromCharCode(...data.salt));
        const ciphertextBase64 = btoa(String.fromCharCode(...new Uint8Array(data.ciphertext)));
        return JSON.stringify({ iv: ivBase64, salt: saltBase64, ciphertext: ciphertextBase64 });
    }

    decodeEncryptedData(encoded: string): { iv: Uint8Array; salt: Uint8Array; ciphertext: ArrayBuffer } {
        try {
            const parsed = JSON.parse(encoded);
            const iv = new Uint8Array(atob(parsed.iv).split('').map(c => c.charCodeAt(0)));
            const salt = new Uint8Array(atob(parsed.salt).split('').map(c => c.charCodeAt(0)));
            const ciphertext = new Uint8Array(atob(parsed.ciphertext).split('').map(c => c.charCodeAt(0))).buffer;
            return { iv, salt, ciphertext };
        } catch {
            throw new Error('Invalid encrypted data format');
        }
    }

    async encryptSingleFile(file: TFile, password: string) {
        if (!isTargetDailyNotePath(file.path, this.plugin.settings.dailyNotesFolder)) {
            new Notice(
                `Only ${this.folderPath()}/YYYY-MM-DD.md files can be encrypted. Set "Daily notes folder" in plugin settings if needed.`
            );
            return;
        }

        const content = await this.app.vault.read(file);
        const parsed = parseDailySection(content);
        if (!parsed) {
            return;
        }

        if (isDailyBodyBracketCipher(parsed.dailyBody)) {
            return;
        }
        if (isDailyBodyEmptyOrPlaceholder(parsed.dailyBody)) {
            return;
        }

        const encryptedData = await this.encryptContent(parsed.dailyBody, password);
        const encodedData = this.encodeEncryptedData(encryptedData);
        const newBody = `[${encodedData}]`;
        const finalContent = replaceDailySectionBody(content, newBody);
        if (finalContent === null) {
            return;
        }

        await this.app.vault.modify(file, finalContent);
        new Notice('## Daily encrypted.');
    }

    async decryptSingleFile(file: TFile, password: string) {
        if (!isTargetDailyNotePath(file.path, this.plugin.settings.dailyNotesFolder)) {
            new Notice(
                `Only ${this.folderPath()}/YYYY-MM-DD.md files can be decrypted. Set "Daily notes folder" in plugin settings if needed.`
            );
            return;
        }

        const content = await this.app.vault.read(file);
        const parsed = parseDailySection(content);
        if (!parsed) {
            return;
        }

        const payload = getBracketPayloadFromDailyBody(parsed.dailyBody);
        if (payload === null) {
            new Notice('## Daily is not in […] ciphertext format.');
            return;
        }

        const encryptedData = this.decodeEncryptedData(payload);
        const decryptedBody = await this.decryptContent(encryptedData, password);
        const finalContent = replaceDailySectionBody(content, decryptedBody);
        if (finalContent === null) {
            return;
        }

        await this.app.vault.modify(file, finalContent);
        new Notice('## Daily decrypted.');
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
            .setName('Daily notes folder')
            .setDesc(
                'Vault path to the folder containing YYYY-MM-DD daily notes (e.g. Journey/Daily or Daily). Only that folder and the ## Daily section are affected.'
            )
            .addText(text => text
                .setPlaceholder('Daily/')
                .setValue(this.plugin.settings.dailyNotesFolder)
                .onChange(async (value) => {
                    this.plugin.settings.dailyNotesFolder = normalizeDailyNotesFolderPath(value);
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('Store Password')
            .setDesc('WARNING: Storing passwords is not recommended for security. Only enable if you understand the risks.')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.storePassword)
                .onChange(async (value) => {
                    this.plugin.settings.storePassword = value;
                    if (!value) {
                        this.plugin.settings.encryptionKey = '';
                    }
                    await this.plugin.saveSettings();
                    this.display();
                }));

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
