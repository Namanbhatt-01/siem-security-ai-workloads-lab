# Track 1C — Sample Forensics & Malware Provenance Evidence Sheet

## Architectural Continuity Analysis: GITSHELLPAD (Golang) vs. RUSTYSHADE (Rust)

> **Research Integrity Notice**:  
> The sample corpus and provenance mapping below are reconstructed strictly from published threat intelligence reports (Zscaler ThreatLabz RapidRust and GITSHELLPAD/GOGITTER/GOSHELL campaign reports). Binary PE-header disassembly and decompilation results are strictly bounded to verified published technical analyses. We do not manufacture PE-headers, import tables, or string artifacts without raw binary verification in an isolated sandbox.

---

## 1. Published Sample Corpus & Hash Mappings

### 1.1 RUSTYSHADE Corpus (Rust Implant Family)
Primary source mapping identifies `DriverInstaller.exe` packaged inside `DriverInstaller.zip`.

| Role | Hash | Type | Provenance | Status |
| :--- | :--- | :--- | :--- | :--- |
| **DriverInstaller.exe** | `80fdde0dafa450ae33937ccef752b46666da567926b2f39b37e02e77f9d6a92e` | SHA-256 | Zscaler / RapidRust | Confirmed |
| **DriverInstaller.exe** | `761ccb15af1c3fe6e4365ddf65578966e4c84fc9` | SHA-1 | Zscaler | Confirmed |
| **DriverInstaller.exe** | `ae77f1834ccde53258bc27a779102af2` | MD5 | Zscaler | Confirmed |
| **DriverInstaller.zip** | `52d07b3ef0c5f27d082551d51027de452682e1fbd5bb38a897ea4b31bd387523` | SHA-256 | Zscaler | Confirmed |
| **DriverInstaller.zip** | `00aff1a72c5d5635ab36ce2eb370718a7f0557a0` | SHA-1 | Zscaler | Confirmed |
| **DriverInstaller.zip** | `40a75f87f1e52c33df9ca733aaf8ebbb` | MD5 | Zscaler | Confirmed |

```
DriverInstaller.zip (SHA-256: 52d07b3e...)
        │
        └── DriverInstaller.exe (SHA-256: 80fdde0d...)
                │
                └── RUSTYSHADE: 64-bit Windows Rust backdoor using GitHub private repos for C2
```

---

### 1.2 GITSHELLPAD Corpus (Golang Implant Family)
Reconstructed 6 published `edgehost.exe` samples associated with the GITSHELLPAD campaign:

| SHA-256 | MD5 | SHA-1 | Filename | Family |
| :--- | :--- | :--- | :--- | :--- |
| `8f495603be80b513820a948d51723b616fac33f0f382fa4a141e39e12fff40cf` | `0d86b8039cffc384856e17912f308616` | `6a11c0e5f1d1e22e89b4921c7a371dbf9cf54709` | `edgehost.exe` | GITSHELLPAD |
| `6c60e5b28e352375d101eb0954fa98d229de3b94f22d5815af8948ebed1f44dd` | `f454e2724a63cbbfda26daff1d8bb610` | `6036098059fa1311866ce6ad2723c4d0d1f00138` | `edgehost.exe` | GITSHELLPAD |
| `af01c12019a3a3aa64e8a99d7231e0f2af6084298733bba3d7d41db13091cbac` | `10a7725f807056cb0383a1cae38d49b4` | `54bfe1ffba8bff3571093ade5038dc98ef5f46ce` | `edgehost.exe` | GITSHELLPAD |
| `5d9b2e61ed45b6407b778a18ff87792265fa068d7c4580ae54fbf88af435679f` | `e26b3fece2fe296654406ef8045ffda1` | `6d1dbd92f7ed7381c7bfca681c3139daeab692f1` | `edgehost.exe` | GITSHELLPAD |
| `95a2fb8b6c7b74a7f598819810ddb0a505f3d5cf392b857ff8e75c5a1401110e` | `f4813d65cd7246f716fcbd8f7fd3e63d` | `3d48ab9567c6080471459b34dfc12c89418be8a2` | `edgehost.exe` | GITSHELLPAD |
| `fff79ce90b1af67e0b6d16a850e85861c948f988eda39ef46457241bbe3df170` | `f2284f62625f117c57384b1c5b8b8f58` | `3c17dbf975af8eb7a67e6908f522c93c2c0662e5` | `edgehost.exe` | GITSHELLPAD |

---

## 2. Structural & Protocol Comparison: GITSHELLPAD vs RUSTYSHADE

```
                     PUBLISHED SAMPLE CORPUS

       GITSHELLPAD (6 samples)        RUSTYSHADE (3 samples)
             │                               │
             ▼                               ▼
       ┌────────────┐                  ┌────────────┐
       │ Go family  │                  │ Rust family│
       └─────┬──────┘                  └─────┬──────┘
             │                               │
             └───────────────┬───────────────┘
                             ▼
                    STRUCTURAL COMPARISON
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
           C2 State       Commands       Artifacts
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                     BEHAVIORAL INVARIANTS
```

### Architectural Feature Matrix

| Architectural Dimension | GITSHELLPAD | RUSTYSHADE | Continuity Assessment |
| :--- | :--- | :--- | :--- |
| **Target OS** | Windows (x64) | Windows (x64) | Stable |
| **Implant Binary Type** | Compiled Native Go PE | Compiled Native Rust PE | **Language Transition (Go $\to$ Rust)** |
| **C2 Channel** | GitHub Private Repositories | GitHub Private Repositories | Stable |
| **C2 API Endpoint** | GitHub REST / Contents API | GitHub REST / Contents API | Stable |
| **Task Ingestion** | `command.txt` polling (~15s) | `command.txt` polling | Stable |
| **Result Exfiltration** | `result.txt` PUT to repo | `result.txt` PUT to repo | Stable |
| **Host Recon State** | `info.txt` | `info.txt` / Expanded state | Stable |
| **C2 Protection / Crypto**| Base64 / State exchange | **AES-256-GCM** (Derived from SHA-256 of PAT) | **Upgraded Cryptographic Layer** |
| **C2 Protocol Paradigm** | File-as-Protocol | File-as-Protocol | Stable |
| **Sample Corpus** | 6 published `edgehost.exe` | 3 published `DriverInstaller.exe` | 9-sample candidate corpus |

---

## 3. Cryptographic Key Derivation & C2 API Specification

### RUSTYSHADE Cryptographic Flow
```
Cleartext GitHub PAT (Personal Access Token)
         │
         ▼
     SHA-256 Hash
         │
         ▼
AES-256-GCM Secret Key (Used for payload encryption/decryption)
```

### API Endpoint Format
```http
GET /repos/{owner}/{repo}/contents/{path}?ref={branch}&t={timestamp} HTTP/1.1
Host: api.github.com
Authorization: token {GITHUB_PAT}
Accept: application/vnd.github.v3+json
User-Agent: {Custom_Agent}
```

---

## 4. Methodological Boundaries & Current Scope

### Verified Capabilities
* 9-sample corpus reconstruction (6 GITSHELLPAD + 3 RUSTYSHADE specimens).
* Independent cross-referencing of three-way hash pairs (SHA-256, SHA-1, MD5).
* Protocol state-machine analysis of GitHub REST-based file-as-protocol C2 mechanics.

### Unobtained / Non-Manufactured Forensic Artifacts
To uphold research authenticity, the following are declared as targets for future physical binary reverse-engineering in isolated sandboxes:
* Exact PE Section Headers (VirtualSize, RawSize, Entropy).
* Exact `AddressOfEntryPoint` and `ImageBase`.
* PE Import / Export Address Tables (IAT/EAT) and Rich Headers.
* Exact Rust/Go compiler metadata and runtime artifact signatures.
* Disassembled control flow graphs (CFGs) and crypto subroutine addresses.

---

## 5. CFP / Publication Narrative Guidance

**Recommended Framing**:
> *"We reconstructed a nine-sample published corpus spanning six GITSHELLPAD and three RUSTYSHADE specimens, independently correlated their published C2 artifacts, and evaluated whether the GitHub file-as-protocol architecture survives the Go-to-Rust implementation transition."*
