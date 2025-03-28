# Nostringer CLI

A command-line interface for the [nostringer](https://github.com/AbdelStark/nostringer-rs) ring signature library, allowing you to create and verify anonymous ring signatures with secp256k1 keys.

## Installation

### From Source

```bash
cargo install --path crates/nostringer_cli
```

Or build from the repository:

```bash
git clone https://github.com/AbdelStark/nostringer-rs.git
cd nostringer-rs
cargo install --path crates/nostringer_cli
```

## Usage

The CLI offers several commands to work with ring signatures:

### Generate a Keypair

```bash
# Generate a keypair with x-only public key (default)
nostringer_cli generate

# Generate a keypair with compressed public key
nostringer_cli generate --format compressed

# Generate a keypair and save to file
nostringer_cli generate --output keys.json
```

### Sign a Message

```bash
# Sign a message with your private key and a ring of public keys
nostringer_cli sign \
  --message "This is a secret message" \
  --private-key YOUR_PRIVATE_KEY_HEX \
  --ring "PUBKEY1,PUBKEY2,PUBKEY3" \
  --output signature.json
```

### Verify a Signature

```bash
# Verify a signature against a message and ring
nostringer_cli verify \
  --message "This is a secret message" \
  --c0 SIGNATURE_C0_HEX \
  --s-values "S_VALUE1,S_VALUE2,S_VALUE3" \
  --ring "PUBKEY1,PUBKEY2,PUBKEY3"
```

### Run a Demo

```bash
# Run an end-to-end demo of the ring signature process
nostringer_cli demo

# Run a demo of the linkable BLSAG variant (with key images)
nostringer_cli blsag-demo
```

## Examples

Here's a complete example workflow:

```bash
# 1. Generate keypairs for ring members
nostringer_cli generate > ring_member1.txt
nostringer_cli generate > ring_member2.txt
nostringer_cli generate > ring_member3.txt

# 2. Extract public keys for the ring
PUBKEY1=$(grep "Public Key" ring_member1.txt | awk '{print $3}')
PUBKEY2=$(grep "Public Key" ring_member2.txt | awk '{print $3}')
PUBKEY3=$(grep "Public Key" ring_member3.txt | awk '{print $3}')
RING="$PUBKEY1,$PUBKEY2,$PUBKEY3"

# 3. Sign a message with the second member's private key
PRIVKEY2=$(grep "Private Key" ring_member2.txt | awk '{print $3}')
nostringer_cli sign \
  --message "Top secret message from the ring" \
  --private-key "$PRIVKEY2" \
  --ring "$RING" \
  --output signature.json

# 4. Verify the signature
C0=$(grep '"c0":' signature.json | cut -d'"' -f4)
S_VALUES=$(grep -A 10 '"s":' signature.json | grep '"' | cut -d'"' -f2 | tr '\n' ',' | sed 's/,$//')

nostringer_cli verify \
  --message "Top secret message from the ring" \
  --c0 "$C0" \
  --s-values "$S_VALUES" \
  --ring "$RING"
```

## License

This project is licensed under the [MIT License](../../LICENSE). 