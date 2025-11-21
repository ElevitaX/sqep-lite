# **LICENSE-NOTICE.md**

```markdown
# ⚠️ Security Disclaimer & Cryptography Warning

SQEP Lite is a **research-grade cryptographic system**.  
Although it uses modern and academically established primitives (ChaCha20-Poly1305, HKDF-SHA256, secure RNG, authenticated framing), the **overall construction is novel** and **not yet formally audited**.  
It must therefore be considered **experimental**.

---

## 🚫 No Warranty

This software is provided **“as-is”**, without any express or implied warranty.

Neither the authors, contributors, nor the ElevitaX organization guarantee:

- That the implementation is free of bugs  
- That the system is free of timing or side-channel vulnerabilities  
- That the algorithms meet jurisdiction-specific regulatory or compliance standards  
- That encrypted data cannot be recovered by third parties  
- That the cryptographic design resists professional cryptanalysis  

Use of this library is **entirely at your own risk**.

---

## 🔐 Cryptography Warning

Custom cryptographic constructions—no matter how carefully implemented—**always carry risk**.

Even though SQEP Lite uses trusted primitives:

- HKDF-SHA256  
- ChaCha20-Poly1305  
- Deterministic, domain-separated KDF expansion  

…the **composition itself**:

- Has **not** undergone external professional review  
- Has **not** received full independent cryptographic auditing  
- May contain subtle mathematical or implementation weaknesses  
- Must be independently evaluated before production deployment  

Do **not** treat SQEP Lite as a drop-in replacement for standardized or widely deployed primitives (AES-GCM, RSA, Curve25519, etc.) without independent verification.

---

## 🔍 Audit & Review Recommended

Before deploying SQEP Lite in commercial, financial, industrial, or safety-critical systems, you should obtain:

- A **cryptographic/cryptanalysis review**  
- A **secure code audit**  
- A **penetration test** or **crypto-specific assessment**  

The SQEP Lite project encourages professional review and responsible disclosure.

---

## 🔒 Key Management Warning

Cryptography is **instantly compromised** if key management is mishandled.

You must ensure:

- Keys are generated using secure randomness  
- Keys are stored only in secure storage (HSM, enclave, vault)  
- Keys are rotated properly  
- Keys are never logged, serialized in plaintext, or exposed to untrusted processes  
- Keys are wiped from memory where feasible  

Improper key management **voids all security guarantees**, regardless of algorithm strength.

---

## 🧪 Experimental Features

Any module gated behind Cargo features—such as `"plus"`, `"firewall"`, hybrid mode, or advanced KEM layers—should be considered:

- **Experimental**  
- **Not guaranteed to be secure**  
- **Subject to change without notice**  
- **Unsuitable for production without audit**

---

## 🛡️ Responsible Use

SQEP Lite is intended for **research, education, experimentation, and prototyping**.  
If you deploy it in operational systems, you acknowledge that:

- You understand local cryptography/export laws  
- You have performed proper threat modeling  
- You have validated SQEP Lite against your requirements  
- You accept full responsibility for security outcomes  

---

## 📣 Responsible Disclosure

If you discover a bug, vulnerability, or potential weakness:

1. **Do not disclose it publicly.**  
2. Contact the maintainer privately at:  
   **elevitax@gmail.com**  
3. Provide a clear description and reproduction steps.  
4. A coordinated disclosure plan will be arranged.

Thank you for supporting secure, transparent, and responsible cryptographic development.
```

---
