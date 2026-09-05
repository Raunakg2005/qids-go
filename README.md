# QIDS Go Client SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/Raunakg2005/qids-go.svg)](https://pkg.go.dev/github.com/Raunakg2005/qids-go)
[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/tag/Raunakg2005/qids-go?label=version)](https://github.com/Raunakg2005/qids-go/releases)

**Official Go client SDK for Quantum Digital Signatures (QDS) & Post-Quantum Information-Theoretic Security.**

`qids-go` provides high-performance, asynchronous and synchronous Go bindings for signing transactions, validating signature tags in sub-millisecond latency, and ingesting quantum key material via ETSI GS QKD 014 standards.

---

## Installation

```bash
go get github.com/Raunakg2005/qids-go@v1.3.2
```

*Requirements: Go 1.21 or higher.*

---

## Quickstart

### 1. Initialize Client & Sign a Document

```go
package main

import (
	"context"
	"fmt"
	"log"

	qids "github.com/Raunakg2005/qids-go"
)

func main() {
	// Initialize client for your node
	client := qids.NewQIDSClient("https://qids-gateway.internal.net", "bank_node_alpha")

	// 1. Sign a transaction or document payload
	payload := []byte("TRANSFER 1,000,000 USD TO ACCT-48910")
	signResult, err := client.Sign(context.Background(), "DOC-98104", payload, []string{"bank_node_beta"})
	if err != nil {
		log.Fatalf("Sign failed: %v", err)
	}

	fmt.Printf("Signed Document: %s\n", signResult.DocumentID)
	fmt.Printf("Generated %d recipient signature tag(s)\n", len(signResult.SignatureTags))

	// 2. Designated recipient verifies signature tag
	verifyResult, err := client.Verify(
		context.Background(),
		signResult.DocumentID,
		payload,
		"bank_node_alpha",
		signResult.SignatureTags[0],
	)
	if err != nil {
		log.Fatalf("Verify failed: %v", err)
	}

	fmt.Printf("Verification Verdict: %s (Valid: %t)\n", verifyResult.Reason, verifyResult.IsValid)
	// Output: Verification Verdict: ACCEPTED (Valid: true)
}
```

---

## Core Capabilities

- **Information-Theoretic Security**: Immunity against quantum computer attacks (Shor's algorithm).
- **Sub-Millisecond Verification**: Ultra-low latency deterministic verification pipeline designed for high-frequency trading.
- **ETSI GS QKD 014 Integration**: Carrier-grade quantum key ingestion.
- **Zero Black-Box AI/ML**: Fully auditable, closed-form deterministic verification.

---

## License

Proprietary and Confidential. Copyright (c) 2026 QIDS. All Rights Reserved. See [LICENSE](LICENSE) for terms.
