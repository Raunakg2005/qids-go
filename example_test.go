package qids_test

import (
	"fmt"
	"log"
	"os"

	qids "github.com/Raunakg2005/qids-go"
)

// Mirrors the README quickstart so the documented usage is compiled on every
// `go test`. No "Output:" comment: it needs a live gateway, so it is built
// but not run here.
func ExampleNewQIDSClientWithKey() {
	client := qids.NewQIDSClientWithKey(os.Getenv("QIDS_GATEWAY_URL"), "bank_node_alpha", os.Getenv("QIDS_API_KEY"))

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
}
