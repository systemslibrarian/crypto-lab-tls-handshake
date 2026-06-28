# Prompt: Create "crypto-lab-tls-handshake-prompt" Demo

You are an expert cryptography educator and frontend developer who creates high-quality, focused, interactive browser-based educational tools.

## Project Goal
Create a new standalone browser demo called **Simplified TLS 1.3 Handshake** that helps students understand how a modern TLS connection is actually established, including the cryptographic primitives involved and the security properties achieved.

## Why This Is Valuable for Students
TLS (especially TLS 1.3) is one of the most widely used cryptographic protocols in the world, yet many students graduate without a clear picture of how the full handshake works. They often learn individual primitives (Diffie-Hellman, signatures, AEAD) in isolation but struggle to see how they fit together in a real protocol.

A good interactive TLS handshake demo should allow students to:
- See the sequence of messages in a real TLS 1.3 handshake
- Understand the purpose of each step (key exchange, authentication, forward secrecy, etc.)
- Observe how cryptographic primitives are combined
- Appreciate why TLS 1.3 is significantly cleaner and more secure than TLS 1.2
- Connect theoretical knowledge to something they use every day (HTTPS)

## Learning Objectives
By using this demo, a student should be able to:
- Describe the main phases of a TLS 1.3 handshake
- Explain the role of Diffie-Hellman (or hybrid) key exchange in TLS 1.3
- Understand how authentication (certificates + signatures) prevents man-in-the-middle attacks
- See how forward secrecy is achieved
- Identify the purpose of the different cryptographic keys derived during the handshake
- Compare TLS 1.3 simplifications to older versions at a high level

## Required Sections & Flow

### 1. TLS 1.3 Overview
- Short, clear explanation of what TLS provides (confidentiality, integrity, authentication) and why version 1.3 is a major improvement.
- Simple diagram showing the high-level flow (ClientHello → ServerHello → ... → Application Data).

### 2. Interactive Handshake Simulator (Core Feature)
- Step-by-step interactive walkthrough of a full TLS 1.3 handshake.
- User can advance one message at a time.
- At each step, show:
  - What message is being sent
  - What cryptographic operations are happening
  - What keys/secrets are being derived or used
  - Security properties achieved so far

### 3. Key Exchange Phase (Detailed)
- Focus on Diffie-Hellman (or hybrid key exchange) in TLS 1.3.
- Show how the client and server agree on a shared secret.
- Optionally allow switching between classical DH and a hybrid post-quantum option.

### 4. Authentication Phase
- Show how the server proves its identity using certificates and signatures.
- Explain why this step is critical to prevent man-in-the-middle attacks.
- Simple visualization of certificate chain validation.

### 5. Key Derivation & Forward Secrecy
- Show how multiple keys are derived from the shared secret (using HKDF).
- Highlight how forward secrecy works in TLS 1.3 (different keys for each session).
- Contrast with non-forward-secret key exchange.

### 6. Record Layer (Simplified)
- Brief view of how application data is protected after the handshake using AEAD (e.g., AES-GCM or ChaCha20-Poly1305).
- Show an example of encrypted application data.

### 7. Comparison / Takeaways
- Key improvements in TLS 1.3 vs TLS 1.2 (simplified handshake, removed legacy algorithms, better forward secrecy by default).
- Common real-world issues or misconfigurations.

## Technical Preferences
- Browser-native (HTML + TypeScript/JavaScript).
- The demo should feel realistic but remain educational and simplified — not a full protocol implementation.
- Use clear visual flow (timeline, message sequence diagram, or step cards).
- Allow users to explore at their own pace with good explanations at each step.
- Clean, professional, educational aesthetic consistent with Crypto Lab.

## Relationship to Existing Work
- This should complement (not duplicate) existing protocol demos such as `SSH Handshake`, `Noise Pipe`, `Ratchet Wire`, or `Hybrid Wire`.
- It can reference or link to more specialized demos (e.g., hybrid key exchange, certificate validation) where appropriate.
- Keep the scope focused on the **handshake process** and how cryptography is used within it.

## Output Requested
Please provide:
1. A recommended final display title for the demo page
2. High-level architecture and component breakdown
3. Key interactive elements and how the handshake simulation should work
4. Suggested visualizations (message flow, key derivation diagram, etc.)
5. How much realism vs simplification is appropriate
6. Any important pedagogical notes or common student misconceptions this demo should address

Start with the proposed structure, then we can iterate on implementation details.
