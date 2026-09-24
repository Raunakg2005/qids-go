# QIDS Go Client SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/Raunakg2005/qids-go.svg)](https://pkg.go.dev/github.com/Raunakg2005/qids-go)
[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/tag/Raunakg2005/qids-go?label=version)](https://github.com/Raunakg2005/qids-go/releases)

**Official Go client for Quantum Digital Signatures (QDS) through a QIDS gateway.**

Signing and verification run on the gateway: the one-time universal-hash key is what makes a tag unforgeable, so a client able to compute tags locally could also forge them. This package authenticates to the gateway, sends your payload as its exact bytes, and also ships the local primitives (Toeplitz hashing, Wald SPRT) and an ETSI GS QKD 014 key-management client.

---

## Installation

```bash
go get github.com/Raunakg2005/qids-go@v1.3.3
```

*Requirements: Go 1.21 or higher.*

---

## Quickstart: sign and verify

```go
package main

import (
	"fmt"
	"log"
	"os"

	qids "github.com/Raunakg2005/qids-go"
)

func main() {
	client := qids.NewQIDSClientWithKey(
		os.Getenv("QIDS_GATEWAY_URL"), // your gateway's base URL
		"bank_node_alpha",
		os.Getenv("QIDS_API_KEY"), // sk_live_... / sk_test_...
	)

	payload := []byte("TRANSFER 1,000,000 USD TO ACCT-48910")
	sig, err := client.Sign("DOC-98104", payload, []string{"bank_node_beta"})
	if err != nil {
		log.Fatalf("sign: %v", err)
	}
	tag := sig.SignatureTags[0]

	res, err := client.Verify(sig.DocumentID, payload, tag.HashTag, tag.KeyID)
	if err != nil {
		log.Fatalf("verify: %v", err)
	}
	fmt.Printf("valid=%t status=%s reason=%s\n", res.IsValid, res.Status, res.Reason)
	// valid=true status=ACCEPTED reason=ok
}
```

Document IDs are write-once per tenant: signing the same ID twice returns HTTP 409.
Payloads are sent as `payload_b64`, so binary documents are signed byte-for-byte.

---

## What's in the package

- **Gateway client**: `NewQIDSClientWithKey`, `Sign`, `Verify`. Every call carries `Authorization: Bearer <API_KEY>`.
- **ETSI GS QKD 014 client**: `NewETSI014Client`, `GetStatus`, `GetEncKeys`, `GetDecKeys`, for talking to a key-management entity directly.
- **Primitives**: `ToeplitzHash64` (64-bit Toeplitz/LFSR universal hashing) and `NewSequentialTest` (Wald SPRT), both closed-form with no ML.

---

## License

Proprietary and Confidential. Copyright (c) 2026 QIDS. All Rights Reserved. See [LICENSE](LICENSE) for terms.
