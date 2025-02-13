use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
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
use argon2::{
    password_hash::{
        rand_core::OsRng,
         PasswordHasher, SaltString
    },
    Argon2
};
use clipboard_win::{formats, set_clipboard};
use rand::Rng;
use rand::RngCore;
use zeroize::Zeroize;
use thiserror::Error;

const SESSION_TIMEOUT_SECONDS: u64 = 900;
const MIN_PASSWORD_LENGTH: usize = 8;
const MAX_FAILED_ATTEMPTS: u32 = 3;

#[derive(Error, Debug)]
pub enum LockerError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Invalid password: {0}")]
    InvalidPassword(String),
    #[error("Too many failed attempts")]
    TooManyAttempts,
    #[error("Clipboard error: {0}")]
    Clipboard(String),
}

type Result<T> = std::result::Result<T, LockerError>;

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
    /// Generate a secure password
    Generate { 
        /// Length of the password
        #[arg(default_value = "16")]
        length: usize,
        /// Save generated password for an app
        app: Option<String> 
    },
}

#[derive(Serialize, Deserialize)]
struct PasswordStore {
    passwords: HashMap<String, (Vec<u8>, [u8; 12])>,
    master_key_salt: String,
    failed_attempts: u32,
}

impl PasswordStore {
    fn load(file_path: &PathBuf) -> Result<Self> {
        if let Ok(mut file) = OpenOptions::new().read(true).open(file_path) {
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            Ok(serde_json::from_str(&contents).unwrap_or_else(|_| Self {
                passwords: HashMap::new(),
                master_key_salt: SaltString::generate(&mut OsRng).to_string(),
                failed_attempts: 0,
            }))
        } else {
            Ok(Self {
                passwords: HashMap::new(),
                master_key_salt: SaltString::generate(&mut OsRng).to_string(),
                failed_attempts: 0,
            })
        }
    }

    fn save(&self, file_path: &PathBuf) -> Result<()> {
        let json = serde_json::to_string(self).map_err(|e| LockerError::Io(io::Error::new(io::ErrorKind::Other, e)))?;
        fs::write(file_path, json).map_err(LockerError::Io)
    }

    fn verify_password_strength(password: &str) -> Result<()> {
        if password.len() < MIN_PASSWORD_LENGTH {
            return Err(LockerError::InvalidPassword(format!(
                "Password must be at least {} characters long",
                MIN_PASSWORD_LENGTH
            )));
        }
        
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_digit(10));
        let has_special = password.chars().any(|c| !c.is_alphanumeric());
        
        if !(has_upper && has_lower && has_digit && has_special) {
            return Err(LockerError::InvalidPassword(
                "Password must contain uppercase, lowercase, number, and special character".to_string()
            ));
        }
        
        Ok(())
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

fn derive_key(password: &str, salt: &str) -> Result<Vec<u8>> {
    let salt = SaltString::from_b64(salt).map_err(|e| LockerError::Encryption(e.to_string()))?;
    let argon2 = Argon2::default();
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| LockerError::Encryption(e.to_string()))?;
    
    Ok(password_hash.hash.unwrap().as_bytes().to_vec())
}

fn encrypt_password(password: &str, master_key: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    let key = Key::<Aes256Gcm>::from_slice(master_key);
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), password.as_bytes())
        .map_err(|e| LockerError::Encryption(e.to_string()))?;
    
    Ok((ciphertext, nonce))
}

fn decrypt_password(encrypted: &(Vec<u8>, [u8; 12]), master_key: &[u8]) -> Result<String> {
    let (ciphertext, nonce) = encrypted;
    let key = Key::<Aes256Gcm>::from_slice(master_key);
    let cipher = Aes256Gcm::new(key);

    let decrypted = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext.as_slice())
        .map_err(|e| LockerError::Decryption(e.to_string()))?;
    
    String::from_utf8(decrypted)
        .map_err(|e| LockerError::Decryption(e.to_string()))
}

fn copy_to_clipboard(text: &str) -> Result<()> {
    set_clipboard(formats::Unicode, text)
        .map_err(|e| LockerError::Clipboard(e.to_string()))
}

fn generate_random_asterisks(min: usize, max: usize) -> String {
    let mut rng = rand::thread_rng();
    let count = rng.gen_range(min..=max);
    "*".repeat(count)
}

fn generate_password(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    let mut rng = rand::thread_rng();
    let password: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    
    // Ensure password meets complexity requirements
    if !password.chars().any(|c| c.is_uppercase()) ||
       !password.chars().any(|c| c.is_lowercase()) ||
       !password.chars().any(|c| c.is_digit(10)) ||
       !password.chars().any(|c| !c.is_alphanumeric()) {
        // If requirements not met, generate again
        return generate_password(length);
    }
    
    password
}

fn get_master_key(store: &mut PasswordStore, store_path: &PathBuf) -> Vec<u8> {
    if let Some(session) = load_session() {
        session.master_key
    } else {
        println!("Enter master key:");
        let master_password = read_password().expect("Failed to read master key");
        match derive_key(&master_password, &store.master_key_salt) {
            Ok(key) => {
                store.failed_attempts = 0;
                if let Err(e) = store.save(store_path) {
                    eprintln!("Failed to update store: {}", e);
                }
                save_session(&Session::new(key.clone()));
                key
            }
            Err(_e) => {
                store.failed_attempts += 1;
                if let Err(e) = store.save(store_path) {
                    eprintln!("Failed to update store: {}", e);
                }
                eprintln!("Invalid master key");
                std::process::exit(1);
            }
        }
    }
}

fn main() {
    let args = Cli::parse();
    let store_path = get_store_path();
    
    let mut store = match PasswordStore::load(&store_path) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("Failed to load password store: {}", e);
            return;
        }
    };

    if store.failed_attempts >= MAX_FAILED_ATTEMPTS {
        eprintln!("Too many failed attempts. Please wait or reset the store.");
        return;
    }

    if let Commands::Generate { length, app } = args.command {
        let password = generate_password(length);
        if let Some(app_name) = app {
            // If app specified, we need master key to store it
            let master_key = get_master_key(&mut store, &store_path);
            match encrypt_password(&password, &master_key) {
                Ok(encrypted) => {
                    store.passwords.insert(app_name.clone(), encrypted);
                    if let Err(e) = store.save(&store_path) {
                        eprintln!("Failed to save password: {}", e);
                        return;
                    }
                    println!("Generated and stored password for {}", app_name);
                }
                Err(e) => {
                    eprintln!("Failed to store generated password: {}", e);
                    return;
                }
            }
        }
        if let Err(e) = copy_to_clipboard(&password) {
            eprintln!("Generated password but failed to copy to clipboard: {}", e);
            println!("Generated password: {}", password);
        } else {
            println!("Generated password copied to clipboard");
        }
        return;
    }

    // Get master key for other commands
    let master_key = get_master_key(&mut store, &store_path);

    match args.command {
        Commands::Add { app, password } => {
            if let Err(e) = PasswordStore::verify_password_strength(&password) {
                eprintln!("Invalid password: {}", e);
                return;
            }
            
            match encrypt_password(&password, &master_key) {
                Ok(encrypted) => {
                    store.passwords.insert(app.clone(), encrypted);
                    if let Err(e) = store.save(&store_path) {
                        eprintln!("Failed to save password: {}", e);
                        return;
                    }
                    println!("Password for {} added successfully", app);
                }
                Err(e) => eprintln!("Failed to encrypt password: {}", e),
            }
        }
        Commands::Get { app } => {
            if let Some(encrypted) = store.passwords.get(&app) {
                match decrypt_password(encrypted, &master_key) {
                    Ok(decrypted) => {
                        if let Err(e) = copy_to_clipboard(&decrypted) {
                            eprintln!("Failed to copy to clipboard: {}", e);
                            return;
                        }
                        let asterisks = generate_random_asterisks(8, 16);
                        println!("Password for {} is {} (copied to clipboard)", app, asterisks);
                    }
                    Err(e) => eprintln!("Failed to decrypt password: {}", e),
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
                if let Err(e) = store.save(&store_path) {
                    eprintln!("Failed to save password store: {}", e);
                }
                println!("Password for {} deleted successfully", app);
            } else {
                println!("No password found for {}", app);
            }
        }
        _ => unreachable!(),
    }
}
