# Digital Certified Mail: Secure Certified Delivery

## Overview

This project is a Java 17 / Spring Boot implementation of a digital certified mail workflow for secure contract delivery. It combines a browser-based web application with a socket-based delivery server to support:

- secure sender-to-recipient file delivery
- recipient-signed receipt before real key release
- sender-verifiable receipt evidence
- recipient decryption proof
- replay protection on signed web requests
- persistent audit logging
- a bogus-message artifact
- an OT-style key-transfer stage

The current UI branding is **Aurum Law**. Lawyers send contracts, clients receive them, sign a receipt, complete the OT-style selection step if applicable, and only then obtain usable access to the real encrypted message.

## What The System Guarantees

The project is designed to preserve these properties in the current implementation:

- The real message stays unreadable until the recipient signs the receipt.
- The sender cannot forge a valid recipient receipt.
- The sender cannot forge a valid recipient decryption proof.
- Message integrity is checked by hashing the decrypted plaintext and comparing it to the stored contract hash.
- Browser requests that fetch sensitive data are signed, freshness-checked, and replay-protected.
- Bogus and real artifacts are stored separately and validated so they cannot be confused.
- Audit logs persist across contracts and sessions and can be viewed globally or per contract.

## Architecture

The project has two runtime components:

1. `web.WebApp`
   - Spring Boot web application
   - serves the UI from `src/main/resources/static`
   - exposes REST endpoints for registration, login, sending, inbox/sent views, receipt handling, OT, released keys, decrypt proof, and audit history

2. `app.ServerMain`
   - socket-based delivery server on port `5050`
   - stores registered public keys and protected contract artifacts
   - validates receipts, OT selections, and decrypt proofs
   - releases wrapped key material only when protocol conditions are satisfied
   - writes persistent audit entries

The web application talks to the delivery server through `web.bridge.BridgeClient`.

## Main Features

### User and Role Model

- Supported roles: `LAWYER`, `CLIENT`
- Only `LAWYER` users can send contracts
- `LAWYER` registration requires an invite code from `web-data/lawyer-reg-code.txt` or `LAWYER_REG_CODE`
- User registration stores:
  - username
  - role
  - public key
  - encrypted private key bundle

### Password / Unlock Key Policy

The unlock key is used by the browser to decrypt the locally stored private key bundle.

### Cryptography

The project uses modern primitives:

- `ECDSA P-256` for signatures
- `ECDH P-256` for deriving wrapping keys
- `AES-256-GCM` for file encryption and wrapped-key encryption
- `SHA-256` for integrity hashing, OT-style commitments, and transfer identifiers
- `PBKDF2-SHA-256` in the browser to derive a key-encryption key for the local private key bundle

Server-side crypto helpers live in [`src/main/java/app/CryptoUtils.java`](/c:/Users/zaina/Documents/Computer%20and%20Software%20Security/secure-certified-delivery/src/main/java/app/CryptoUtils.java).

### Certified Delivery Flow

Current web flow:

1. A lawyer registers or logs in.
2. The lawyer selects a recipient and file in `send.html`.
3. The browser:
   - reads the file
   - computes the plaintext hash
   - generates a random AES file key
   - encrypts the file with AES-GCM
   - wraps the AES key for the recipient using ephemeral ECDH + AES-GCM
   - creates a distinct bogus protected artifact
   - signs the send request
4. The web app forwards the upload to `ServerMain`.
5. The recipient fetches the protected contract in `contract.html`.
6. The recipient clicks `Acknowledge Receipt & Open`.
7. The browser:
   - signs and submits the receipt
   - fetches the OT offer if the contract has OT state
   - signs and submits an OT selection of `REAL`
   - requests the released wrapped key
   - unwraps the AES key
   - decrypts the file
   - verifies integrity by recomputing the SHA-256 hash
   - signs and submits decryption proof

### Bogus Message Support

Each newly sent contract carries:

- one real protected message
- one bogus protected message

The server rejects bogus artifacts that are:

- incomplete
- tagged incorrectly
- identical to the real ciphertext, real hash, or real wrapped key ciphertext

This keeps bogus and real artifacts separated.

### OT-Style Key Transfer Support

The project includes a practical OT-style extension rather than a full standalone cryptographic OT subsystem.

For contracts that include bogus artifacts, the server derives and stores:

- `otProtocolTag`
- `otTransferId`
- `otRealCommitmentB64`
- `otBogusCommitmentB64`

The recipient must submit a signed OT selection bound to:

- `contractId`
- `otTransferId`
- the chosen branch (`REAL` or `BOGUS`)
- a timestamp

### Receipt and Decryption Proof

Receipt payload format:

```text
RECEIPT|<contractId>|<contractHashB64>|<timestampIso>
```

Decryption proof payload format:

```text
DECRYPT_PROOF|<contractId>|<witnessHashB64>|<timestampIso>
```

Both are signed by the recipient using their private key. The server verifies them using the stored public key.

### Replay Protection

Signed web requests in `ContractController` use:

- timestamp freshness checks with a 120-second skew window
- one-time request tracking
- a 10-minute replay cache TTL

This protection applies to signed REST requests such as:

- send
- inbox/sent listing
- contract fetch
- key fetch
- OT offer fetch
- audit fetch
- receipt fetch
- decrypt proof fetch

### Audit Logging

Audit logging is persistent and global.

All existing log creation points write logs and entries are appended to:

- `web-data/audit-log.json`

Each audit entry stores:

- `timestampIso`
- `contractId`
- `eventType`
- `actor`
- `line`

Supported audit views:

- per-contract audit
- global audit history
- global audit search in the UI

Audit results are returned newest first.

## Project Structure

```text
secure-certified-delivery/
├── src/main/java/app/
│   ├── AuditLogStore.java
│   ├── CryptoUtils.java
│   ├── NetUtils.java
│   ├── OtUtils.java
│   ├── Protocol.java
│   ├── RecipientClientMain.java
│   ├── SenderClientMain.java
│   └── ServerMain.java
├── src/main/java/web/
│   ├── WebApp.java
│   ├── api/
│   │   ├── AuthController.java
│   │   ├── ContractController.java
│   │   └── UserController.java
│   ├── bridge/BridgeClient.java
│   ├── store/
│   │   ├── ContractStore.java
│   │   └── UserStore.java
│   └── util/
│       ├── B64.java
│       └── Json.java
├── src/main/resources/static/
│   ├── app.js
│   ├── audit.html
│   ├── contract.html
│   ├── dashboard-client.html
│   ├── dashboard-lawyer.html
│   ├── login.html
│   ├── register.html
│   ├── send.html
│   └── styles.css
├── src/test/java/app/
│   ├── AuditLogStoreTest.java
│   └── OtUtilsTest.java
└── web-data/
    ├── audit-log.json
    ├── contracts-store.json
    ├── contracts.json
    ├── gateway-secret.txt
    ├── lawyer-reg-code.txt
    ├── server-user-keys.json
    └── users.json
```

## Persistent Data Files

The application persists runtime state to `web-data/`:

- `users.json`
  - browser-facing user registry
  - role + public key + encrypted private key bundle

- `contracts.json`
  - lightweight contract index for sent/inbox listing in the web app

- `contracts-store.json`
  - protected contract artifacts stored by the delivery server
  - includes real artifact fields, bogus artifact fields, receipt state, decrypt proof state, and OT state

- `server-user-keys.json`
  - public keys registered with the delivery server

- `audit-log.json`
  - persistent global audit history

- `gateway-secret.txt`
  - shared secret used by the web app gateway to make trusted direct calls to the delivery server

- `lawyer-reg-code.txt`
  - invite code for `LAWYER` registration

## UI Pages

- `login.html`
  - login with username and unlock key

- `register.html`
  - account creation
  - role selection
  - lawyer invite code
  - unlock-key policy enforcement

- `dashboard-lawyer.html`
  - sent contracts
  - per-contract audit
  - evidence verification

- `dashboard-client.html`
  - received contracts inbox

- `send.html`
  - file selection and secure sending by lawyers

- `contract.html`
  - recipient receipt, OT, key retrieval, integrity verification, and file open/download

- `audit.html`
  - global audit history from the nav bar
  - per-contract audit when opened with `?id=<contractId>`
  - global mode when opened with `?global=1`
  - client-side search across displayed logs

## REST API Summary

Main web endpoints:

- `POST /api/login`
- `POST /api/users/register`
- `GET /api/users/{username}/public-key`
- `GET /api/users/{username}/key-bundle`
- `POST /api/contracts/send`
- `GET /api/contracts/sent/{username}`
- `GET /api/contracts/inbox/{username}`
- `GET /api/contracts/{contractId}`
- `POST /api/contracts/{contractId}/receipt`
- `GET /api/contracts/{contractId}/receipt`
- `GET /api/contracts/{contractId}/ot-offer`
- `POST /api/contracts/{contractId}/ot-select`
- `GET /api/contracts/{contractId}/released-key`
- `POST /api/contracts/{contractId}/decrypt-proof`
- `GET /api/contracts/{contractId}/decrypt-proof`
- `GET /api/contracts/{contractId}/audit`
- `GET /api/contracts/audit/history`

Many of these endpoints require a browser-signed payload and timestamp.

## Socket Protocol Summary

Important delivery-server message types in `Protocol.Msg`:

- `REGISTER`
- `AUTH_START`
- `AUTH_CHALLENGE`
- `AUTH_PROVE`
- `UPLOAD_CONTRACT`
- `GET_CONTRACT`
- `SUBMIT_RECEIPT`
- `GET_RELEASED_KEY`
- `GET_RECEIPT`
- `SUBMIT_DECRYPT_PROOF`
- `GET_DECRYPT_PROOF`
- `GET_OT_OFFER`
- `SUBMIT_OT_SELECTION`
- `GET_AUDIT`

## How To Run

### Prerequisites

- Java 17
- Maven 3.x

### Start The Delivery Server

```bash
mvn --% exec:java -Dexec.mainClass=app.ServerMain
```

### Start The Web Application

In a second terminal:

```bash
mvn --% spring-boot:run
```

The Spring Boot app serves the UI and API. The delivery server must also be running because the web app delegates contract protocol operations to it.

## Tests

### Running Tests

Run all tests:

```bash
mvn test
```

Run quietly (without verbose output):

```bash
mvn -q test
```

Run a specific test class:

```bash
mvn test -Dtest=ProtocolFlowIntegrationTest
```

Run a specific test method:

```bash
mvn test -Dtest=ProtocolFlowIntegrationTest#uploadContract_acceptsEncryptedPayloadAndPersistsContract
```

Create a package without running tests:

```bash
mvn -q -DskipTests package
```

### Test Classes

#### Unit Tests

- **`AuditLogStoreTest.java`**
  - Tests audit log creation, persistence, and descending order retrieval
  - Validates per-contract and global audit filtering

- **`CryptoUtilsTest.java`**
  - Tests cryptographic primitives: key generation, signing, verification, encryption, decryption
  - Tests key wrapping and unwrapping for recipient key material

- **`OtUtilsTest.java`**
  - Tests OT-style transfer derivation behavior
  - Tests offer and commitment generation

#### Integration Tests

- **`ProtocolFlowIntegrationTest.java`**
  - Tests the complete sender → receipt → OT selection → key release → decrypt flow
  - 8 comprehensive test cases covering happy path and error conditions:
    - Contract upload and persistence
    - Sent/inbox listing
    - Recipient access before receipt (should fail)
    - Valid receipt acceptance
    - Bogus artifact validation
    - OT transfer derivation
    - Key release after receipt
    - Audit log recording

- **`ContractSecurityIntegrationTest.java`**
  - Tests security validations and edge cases
  - 4 security-focused test cases:
    - Invalid audit data validation
    - Gap analysis for contract states
    - OT commitment validation
    - Contract identity verification

- **`ProtocolPerformanceTest.java`**
  - Tests encryption/decryption performance on various file sizes
  - 4 performance test cases:
    - AES-GCM encryption timing (small, medium, large files)
    - Sequential upload performance
    - Key wrapping/unwrapping timing
    - Decryption throughput

### Test Isolation

The test harness (`TestEnvironmentSupport.java`) provides complete isolation:

1. **File Backup/Restore**
   - Backs up `web-data/` files before test suite runs
   - Resets files to clean initial state for testing
   - Restores original files after suite completes
   - Prevents test data from corrupting real application state

2. **In-Memory State Reset**
   - Clears `ServerMain.USER_PUBKEYS` between tests
   - Clears `ServerMain.CONTRACTS` between tests
   - Clears `ServerMain.AUDIT` entries between tests
   - Clears `ContractController.SEEN` replay cache
   - Resets `ContractController.REPLAY_COUNTER` to 0

3. **Server Lifecycle Management**
   - Starts a dedicated test instance of `ServerMain` on port 5050
   - Waits for server to be ready before running tests
   - Cleans up server state after each test
   - All state is automatically restored after test suite completes

### Safe Testing Guidelines

✅ **Safe to run at any time:**
- `mvn test` – completely isolated from the main application
- Tests never modify real application data
- All backing up and restoring happens automatically

⚠️ **Important considerations:**
- Tests start `ServerMain` on port 5050 during execution
- If the main application is already running on port 5050, tests will fail
- **Recommended:** Run tests when the main application is not running
- Test startup adds ~2-3 seconds overhead due to server initialization

### Test Coverage

Current tests cover:

- Cryptographic operations (signing, verification, encryption, decryption)
- Key wrapping and unwrapping for destination recipients
- OT-style transfer derivation and commitment validation
- Audit log persistence, filtering, and descending ordering
- Complete protocol flow from upload through key release
- Receipt validation and signature verification
- Bogus artifact handling and validation
- Replay attack prevention
- Performance metrics for encryption, decryption, and key operations

## Important Security Notes

- This is a course-project implementation, not a production-ready secure mail system.
- There is no external arbitrator or dispute-resolution service.
- The OT support is an OT-style practical extension, not a full standalone cryptographic oblivious transfer protocol.
- Browser login currently checks role existence and relies on private-key unlock for practical access control.
- Private keys for the browser flow are encrypted client-side and stored locally, with a server-backed encrypted bundle copy for recovery on another browser.
- The delivery server trusts the web gateway using `gateway-secret.txt`.

## Known Limitations

- No third-party fair-exchange arbitrator
- No timeout/recovery subsystem for abandoned exchanges
- The CLI and browser key-storage models are different because they serve different demo paths

## Key Source Files

- [`src/main/java/app/ServerMain.java`](/c:/Users/zaina/Documents/Computer%20and%20Software%20Security/secure-certified-delivery/src/main/java/app/ServerMain.java)
- [`src/main/java/app/CryptoUtils.java`](/c:/Users/zaina/Documents/Computer%20and%20Software%20Security/secure-certified-delivery/src/main/java/app/CryptoUtils.java)
- [`src/main/java/app/OtUtils.java`](/c:/Users/zaina/Documents/Computer%20and%20Software%20Security/secure-certified-delivery/src/main/java/app/OtUtils.java)
- [`src/main/java/web/api/ContractController.java`](/c:/Users/zaina/Documents/Computer%20and%20Software%20Security/secure-certified-delivery/src/main/java/web/api/ContractController.java)
- [`src/main/java/web/api/UserController.java`](/c:/Users/zaina/Documents/Computer%20and%20Software%20Security/secure-certified-delivery/src/main/java/web/api/UserController.java)
- [`src/main/resources/static/send.html`](/c:/Users/zaina/Documents/Computer%20and%20Software%20Security/secure-certified-delivery/src/main/resources/static/send.html)
- [`src/main/resources/static/contract.html`](/c:/Users/zaina/Documents/Computer%20and%20Software%20Security/secure-certified-delivery/src/main/resources/static/contract.html)
- [`src/main/resources/static/audit.html`](/c:/Users/zaina/Documents/Computer%20and%20Software%20Security/secure-certified-delivery/src/main/resources/static/audit.html)

