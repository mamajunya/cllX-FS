use clap::{Parser, Subcommand};
use cllx_fs_pro::cli::{EncryptCommand, DecryptCommand, InfoCommand, VerifyCommand};
use cllx_fs_pro::cli::{print_success, print_error};

#[derive(Parser)]
#[command(name = "cllxfs")]
#[command(about = "cllX-FS-Pro: Post-Quantum Secure File System", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 加密 a file
    Encrypt {
        /// Input file path
        #[arg(short, long)]
        input: String,

        /// Output file path
        #[arg(short, long)]
        output: String,

        /// Recipient public keys (can be specified multiple times)
        #[arg(short, long)]
        recipient: Vec<String>,

        /// Chunk size in bytes (default: 1MB)
        #[arg(short, long, default_value = "1048576")]
        chunk_size: usize,

        /// Password for encryption (optional, if not provided a random key will be generated)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// 解密 a file
    Decrypt {
        /// Input file path
        #[arg(short, long)]
        input: String,

        /// Output file path
        #[arg(short, long)]
        output: String,

        /// 私钥 file path
        #[arg(short, long)]
        key: Option<String>,
    },

    /// Show file information
    Info {
        /// Input file path
        #[arg(short, long)]
        input: String,
    },

    /// 验证 file integrity
    Verify {
        /// Input file path
        #[arg(short, long)]
        input: String,
    },

    /// Add recipient to encrypted file
    AddRecipient {
        /// Input file path
        #[arg(short, long)]
        input: String,

        /// Recipient public key
        #[arg(short, long)]
        recipient: String,
    },

    /// Remove recipient from encrypted file
    RemoveRecipient {
        /// Input file path
        #[arg(short, long)]
        input: String,

        /// Recipient ID
        #[arg(short, long)]
        recipient: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Encrypt { input, output, recipient, chunk_size, password } => {
            print_success(&format!("Encrypting {} -> {}", input, output));
            let cmd = EncryptCommand {
                input_path: input,
                output_path: output,
                recipients: recipient,
                chunk_size,
                password,
            };
            cmd.execute()
        }

        Commands::Decrypt { input, output, key } => {
            print_success(&format!("Decrypting {} -> {}", input, output));
            let cmd = DecryptCommand {
                input_path: input,
                output_path: output,
                secret_key_path: key,
            };
            cmd.execute()
        }

        Commands::Info { input } => {
            print_success(&format!("Reading info from {}", input));
            let cmd = InfoCommand {
                input_path: input,
            };
            cmd.execute()
        }

        Commands::Verify { input } => {
            print_success(&format!("Verifying {}", input));
            let cmd = VerifyCommand {
                input_path: input,
            };
            cmd.execute()
        }

        Commands::AddRecipient { input, recipient } => {
            print_success(&format!("Adding recipient to {}", input));
            Ok(())
        }

        Commands::RemoveRecipient { input, recipient } => {
            print_success(&format!("Removing recipient from {}", input));
            Ok(())
        }
    };

    if let Err(e) = result {
        print_error(&format!("{}", e));
        std::process::exit(1);
    }
}
