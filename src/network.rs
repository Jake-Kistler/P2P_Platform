use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

/// sends ciphertext and nonce to the peer using TCP
pub fn send_to_peer(ciphertext: &str, nonce: &str, address: &str) -> Result<(), String> {

    let mut stream = TcpStream::connect(address).map_err(|e| format!("Failed to conect to peer: {}", e))?;

    let payload = format!("{}\n{}", ciphertext, nonce);
    stream.write_all(payload.as_bytes()).map_err(|e| format!("Failed to send payload: {}", e))?;

    Ok(())
}

/// Starts a TCP server that listens for data
pub fn start_server(bind_address: &str) -> Result<(), String> {

    let listener = TcpListener::bind(bind_address).map_err(|e| format!("Failed to start server: {}", e))?;

    println!("Listening on {}", bind_address);

    for stream in listener.incoming() {

        let mut stream = stream.map_err(|e| format!("Stream error: {}", e))?;
        let mut buffer = String::new();

        stream.read_to_string(&mut buffer).map_err(|e| format!("Read error: {}", e))?;

        println!("Received: {}", buffer);
    }

    Ok(())
}