package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	nostr "github.com/fiatjaf/go-nostr"
)

// nonce: rfBd56ti2SMtYvSgD5xAV0YU99zampta7Z7S575KLkIZ9PYkL17LTlsVqMNTZyLK

const alphaBytes = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphaBytes[rand.Intn(len(alphaBytes))]
	}
	return string(b)
}

func main() {
	unsignedNonce := RandStringBytes(64)
	fmt.Printf("Nonce:\t%s\n", unsignedNonce)
	pub, priv := GetKeyPair()
	signedNonce, err := Sign(priv, unsignedNonce)
	if err != nil {
		log.Fatalf("error signing: %s", err)
	}
	checks, err := CheckSignature(signedNonce, unsignedNonce, pub)
	if err != nil {
		log.Fatalf("error checking: %s", err)
	}
	if checks {
		fmt.Println("it's an older code sir, but it checks out")
	} else {
		fmt.Println("something is wrong...")
	}
}

func GetKeyPair() (string, string) {
	priv := nostr.GeneratePrivateKey()
	pub, err := nostr.GetPublicKey(priv)
	if err != nil {
		log.Fatalf("GetPublicKey errored: %s", err)
	}
	return pub, priv
}

// taken from github.com/fiatjaf/go-nostr
func Sign(privateKey string, plainText string) (string, error) {
	h := sha256.Sum256([]byte(plainText))

	s, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("Sign called with invalid private key '%s': %w", privateKey, err)
	}
	sk, _ := btcec.PrivKeyFromBytes(s)
	sig, err := schnorr.Sign(sk, h[:])
	if err != nil {
		return "", err
	}
	signedNonce := hex.EncodeToString(sig.Serialize())
	return signedNonce, nil
}

// taken from github.com/fiatjaf/go-nostr
func CheckSignature(signedNonce, unsignedNonce, unparsedpubkey string) (bool, error) {
	// read and check pubkey
	pk, err := hex.DecodeString(unparsedpubkey)
	if err != nil {
		return false, fmt.Errorf("event pubkey '%s' is invalid hex: %w", unparsedpubkey, err)
	}

	pubkey, err := schnorr.ParsePubKey(pk)
	if err != nil {
		return false, fmt.Errorf("event has invalid pubkey '%s': %w", unparsedpubkey, err)
	}

	// read signature
	s, err := hex.DecodeString(signedNonce)
	if err != nil {
		return false, fmt.Errorf("signature '%s' is invalid hex: %w", signedNonce, err)
	}
	sig, err := schnorr.ParseSignature(s)
	if err != nil {
		return false, fmt.Errorf("failed to parse signature: %w", err)
	}

	// check signature
	hash := sha256.Sum256([]byte(unsignedNonce))
	return sig.Verify(hash[:], pubkey), nil
}
