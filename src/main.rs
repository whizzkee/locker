use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use aes_gcm::{
    aead::Aead,
    Aes256Gcm, Key, Nonce, KeyInit
};
use clap::{Parser, Subcommand};
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use dirs;
use sha2::{Sha256, Digest};
use clipboard_win::{formats, set_clipboard};
use rand::Rng;
use rand::RngCore;
use zeroize::Zeroize;

const SESSION_TIMEOUT_SECONDS: u64 = 900;

#[derive(Parser)]
#[command(name = "password-manager")]
#[command(about = "A tool for managing passwords")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a new password
    Add { app: String, password: String },
    /// Get a password
    Get { app: String },
    /// List all stored apps
    List,
    /// Delete a stored password
    Delete { app: String },
}

#[derive(Serialize, Deserialize)]
struct PasswordStore {
    passwords: HashMap<String, (Vec<u8>, [u8; 12])>,
}

impl PasswordStore {
    fn load(file_path: &PathBuf) -> Self {
        if let Ok(mut file) = OpenOptions::new().read(true).open(file_path) {
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap();
            serde_json::from_str(&contents).unwrap_or_else(|_| Self { passwords: HashMap::new() })
        } else {
            Self { passwords: HashMap::new() }
        }
    }

    fn save(&self, file_path: &PathBuf) {
        let json = serde_json::to_string(self).unwrap();
        fs::write(file_path, json).expect("Failed to save password store");
    }
}

#[derive(Serialize, Deserialize)]
struct Session {
    master_key: Vec<u8>,
    timestamp: u64,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

impl Session {
    fn new(master_key: Vec<u8>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            master_key,
            timestamp,
        }
    }

    fn is_valid(&self) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        current_time - self.timestamp < SESSION_TIMEOUT_SECONDS
    }
}

fn get_store_path() -> PathBuf {
    let mut path = dirs::home_dir().expect("Failed to find home directory");
    path.push(".password-store.json");
    path
}

fn get_session_path() -> PathBuf {
    let mut path = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("locker");
    fs::create_dir_all(&path).unwrap();
    path.push("session.json");
    path
}

fn load_session() -> Option<Session> {
    let session_path = get_session_path();
    if let Ok(mut file) = OpenOptions::new().read(true).open(session_path) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            if let Ok(session) = serde_json::from_str(&contents) {
                let session: Session = session;
                if session.is_valid() {
                    return Some(session);
                }
            }
        }
    }
    None
}

fn save_session(session: &Session) {
    let session_path = get_session_path();
    let contents = serde_json::to_string(session).unwrap();
    fs::write(session_path, contents).unwrap();
}

fn encrypt_password(password: &str, master_key: &[u8]) -> (Vec<u8>, [u8; 12]) {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    let key = Key::<Aes256Gcm>::from_slice(master_key);
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), password.as_bytes())
        .expect("Failed to encrypt password");
    
    (ciphertext, nonce)
}

fn decrypt_password(encrypted: &(Vec<u8>, [u8; 12]), master_key: &[u8]) -> Option<String> {
    let (ciphertext, nonce) = encrypted;
    let key = Key::<Aes256Gcm>::from_slice(master_key);
    let cipher = Aes256Gcm::new(key);

    match cipher.decrypt(Nonce::from_slice(nonce), ciphertext.as_slice()) {
        Ok(decrypted) => String::from_utf8(decrypted).ok(),
        Err(_) => None,
    }
}


fn copy_to_clipboard(text: &str) -> Result<(), Box<dyn std::error::Error>> {
    set_clipboard(formats::Unicode, text).map_err(|e| Box::<dyn std::error::Error>::from(format!("{}", e)))?;
    Ok(())
}


fn generate_random_asterisks(min: usize, max: usize) -> String {
    let mut rng = rand::thread_rng();
    let count = rng.gen_range(min..=max);
    "*".repeat(count)
}

fn main() {
    let args = Cli::parse();
    let store_path = get_store_path();

    let master_key: Vec<u8> = if let Some(session) = load_session() {
        session.master_key.clone()
    } else {
        println!("Enter master key:");
        let master_password = read_password().expect("Failed to read master key");
        let master_key = Sha256::digest(master_password.as_bytes()).to_vec();
        save_session(&Session::new(master_key.clone()));
        master_key
    };

    let mut store = PasswordStore::load(&store_path);

    match args.command {
        Commands::Add { app, password } => {
            let encrypted = encrypt_password(&password, &master_key);
            store.passwords.insert(app.clone(), encrypted);
            store.save(&store_path);
            println!("Password for {} added successfully", app);
        }
        Commands::Get { app } => {
            if let Some(encrypted) = store.passwords.get(&app) {
                if let Some(decrypted) = decrypt_password(encrypted, &master_key) {
                    if let Err(e) = copy_to_clipboard(&decrypted) {
                        println!("Failed to copy to clipboard: {}", e);
                        return;
                    }
                    let asterisks = generate_random_asterisks(8, 16);
                    println!("Password for {} is {} (copied to clipboard)", app, asterisks);
                } else {
                    println!("Failed to decrypt password.");
                }
            } else {
                println!("No password found for {}", app);
            }
        }
        Commands::List => {
            if store.passwords.is_empty() {
                println!("No passwords stored");
            } else {
                for app in store.passwords.keys() {
                    println!("{}", app);
                }
            }
        }
        Commands::Delete { app } => {
            if store.passwords.remove(&app).is_some() {
                store.save(&store_path);
                println!("Password for {} deleted successfully", app);
            } else {
                println!("No password found for {}", app);
            }
        }
    }
}
