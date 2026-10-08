#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]
//! # FrameAssembly
//!
//! A Domain-Specific Language (DSL) for writing deterministic network traffic to `.pcap` files.
//!
//! ## Syntax Guide
//!
//! FrameAssembly uses a strict, keyword-oriented syntax.
//!
//! ### 1. Hosts
//! Hosts act as network endpoints.
//! ```frameassembly
//! HOST example_server { IP 1.2.3.4 MAC 00:11:22:33:44:55 }
//! ```
//!
//! ### 2. Flows
//! Flows encapsulate sequences of packet transmissions between endpoints.
//! ```frameassembly
//! FLOW tcp_handshake(client, server) {
//!     client -> server TCP SYN PAYLOAD "Hello" 
//!     client <- server TCP SYN ACK PAYLOAD "World"
//!     client -> server TCP ACK PAYLOAD "!" 
//! }
//! ```
//!
//! ### 3. Compile Block
//! The `COMPILE` block executes flows.
//! ```frameassembly
//! COMPILE { 
//!     LOOP 100 {
//!         tcp_handshake(example_client, google_dns) 
//!     }
//! }
//! ```

extern crate alloc;

/// AST definitions.
pub mod ast;
/// Backend PCAP generation.
pub mod backend;
/// Compiler error types.
pub mod error;
/// Lexical analysis.
pub mod lexer;
/// Packet building utilities.
pub mod packet;
/// Parsing utilities.
pub mod parser;
/// PCAP file writing.
pub mod pcap;
/// SNMPv3 Cryptography.
pub mod snmp_crypto;
/// SNMP packet builder.
pub mod snmp_builder;
