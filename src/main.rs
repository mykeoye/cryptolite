use crypto_rs::{aes_128_cbc_decrypt, aes_128_ctr_decrypt, decode_hex};

enum Mode {
    CBC,
    CTR,
}
struct Packet<'a> {
    mode: Mode,
    key: &'a str,
    ciphertext: &'a str,
    plaintext: &'a str,
}

fn main() {
    let packets = vec![
        Packet {
            mode: Mode::CBC,
            key: "140b41b22a29beb4061bda66b6747e14",
            ciphertext: "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81",
            plaintext: "Basic CBC mode encryption needs padding."
        },
        Packet {
            mode: Mode::CBC,
            key: "140b41b22a29beb4061bda66b6747e14",
            ciphertext: "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253",
            plaintext: "Our implementation uses rand. IV"
        },
        Packet {
            mode: Mode::CTR,
            key: "36f18357be4dbd77f050515c73fcf9f2",
            ciphertext: "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329",
            plaintext: "CTR mode lets you build a stream cipher from a block cipher."
        },
        Packet {
            mode: Mode::CTR,
            key: "36f18357be4dbd77f050515c73fcf9f2",
            ciphertext: "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451",
            plaintext: "Always avoid the two time pad!"
        },
    ];

    packets.iter().for_each(|packet| {
        let ciphertext = &decode_hex(packet.ciphertext).unwrap();
        let key = &decode_hex(packet.key).unwrap();

        let decrypted_bytes = match packet.mode {
            Mode::CBC => aes_128_cbc_decrypt(&ciphertext, key),
            Mode::CTR => aes_128_ctr_decrypt(&ciphertext, key),
        };

        if let Ok(plaintext) = String::from_utf8(decrypted_bytes) {
            assert_eq!(plaintext, packet.plaintext);
            println!(
                "Decryption of ciphertext {} is '{}' \n",
                packet.ciphertext, plaintext
            );
        } else {
            println!("Decryption of ciphertext {} failed \n", packet.ciphertext);
        }
    });
}
