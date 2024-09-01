// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime/debug"
	"time"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Version can be set at link time to override debug.BuildInfo.Main.Version,
// which is "(devel)" when building from within the module. See
// golang.org/issue/29814 and golang.org/issue/29228.
var Version string

func init() {
	if Version != "" {
		return
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		Version = buildInfo.Main.Version
		return
	}
	Version = "(unknown version)"
}

func connectForSetup() *piv.YubiKey {
	yk, err := openYK()
	if err != nil {
		log.Fatalln("Failed to connect to the YubiKey:", err)
	}
	return yk
}

func runReset(yk *piv.YubiKey) {
	fmt.Print(`Do you want to reset the PIV applet? This will delete all PIV keys. Type "delete": `)
	var res string
	if _, err := fmt.Scanln(&res); err != nil {
		log.Fatalln("Failed to read response:", err)
	}
	if res != "delete" {
		log.Fatalln("Aborting...")
	}

	fmt.Println("Resetting YubiKey PIV applet...")
	if err := yk.Reset(); err != nil {
		log.Fatalln("Failed to reset YubiKey:", err)
	}
}

func runSetup(yk *piv.YubiKey, algo string) {
	if _, err := yk.Certificate(piv.SlotAuthentication); err == nil {
		log.Println("‼️  This YubiKey may already setup (it has a certificate in the Authentication slot!)")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	} else if !errors.Is(err, piv.ErrNotFound) {
		log.Fatalln("Failed to access authentication slot:", err)
	}

	fmt.Println("🔐 The PIN is up to 8 numbers, letters, or symbols. Not just numbers!")
	fmt.Println("❌ The key will be lost if the PIN and PUK are locked after 3 incorrect tries.")
	fmt.Println("")
	fmt.Print("Choose a new PIN/PUK: ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	}
	if len(pin) < 6 || len(pin) > 8 {
		log.Fatalln("The PIN needs to be 6-8 characters.")
	}
	fmt.Print("Repeat PIN/PUK: ")
	repeat, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	} else if !bytes.Equal(repeat, pin) {
		log.Fatalln("PINs don't match!")
	}

	fmt.Println("")
	fmt.Println("🧪 Reticulating splines...")

	var key [24]byte
	if _, err := rand.Read(key[:]); err != nil {
		log.Fatal(err)
	}
	if err := yk.SetManagementKey(piv.DefaultManagementKey, key); err != nil {
		log.Println("‼️  The default Management Key did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}
	if err := yk.SetMetadata(key, &piv.Metadata{
		ManagementKey: &key,
	}); err != nil {
		log.Fatalln("Failed to store the Management Key on the device:", err)
	}
	if err := yk.SetPIN(piv.DefaultPIN, string(pin)); err != nil {
		log.Println("‼️  The default PIN did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}
	if err := yk.SetPUK(piv.DefaultPUK, string(pin)); err != nil {
		log.Println("‼️  The default PUK did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}

	// Function to generate key and certificate for a given slot
	generateKeyAndCert := func(slot piv.Slot, slotName string) {
		var pubKey crypto.PublicKey
		var pivAlgo piv.Algorithm

		// Check firmware version
		version := yk.Version()
		isNewFirmware := version.Major > 5 || (version.Major == 5 && version.Minor >= 7)

		switch algo {
		case "ecp256":
			pivAlgo = piv.AlgorithmEC256
		case "ecp384":
			pivAlgo = piv.AlgorithmEC384
		case "rsa2048":
			pivAlgo = piv.AlgorithmRSA2048
		case "rsa3072":
			if !isNewFirmware {
				log.Fatalf("rsa3072 is only supported on YubiKey firmware 5.7 and above")
			}
			//pivAlgo = piv.AlgorithmRSA3072
			log.Fatalf("rsa3072 not supported yet!")
		case "rsa4096":
			if !isNewFirmware {
				log.Fatalf("rsa4096 is only supported on YubiKey firmware 5.7 and above")
			}
			//pivAlgo = piv.AlgorithmRSA4096
			log.Fatalf("rsa4096 not supported yet!")
		case "ed25519":
			if !isNewFirmware {
				log.Fatalf("ed25519 is only supported on YubiKey firmware 5.7 and above")
			}
			//pivAlgo = piv.AlgorithmEd25519
			log.Fatalf("ed25519 not supported yet!")
		case "x25519":
			if !isNewFirmware {
				log.Fatalf("x25519 is only supported on YubiKey firmware 5.7 and above")
			}
			//pivAlgo = piv.AlgorithmX25519
			log.Fatalf("x25519 not supported yet!")
		default:
			log.Fatalf("Unsupported algorithm: %s", algo)
		}

		pub, err := yk.GenerateKey(key, slot, piv.Key{
			Algorithm:   pivAlgo,
			PINPolicy:   piv.PINPolicyOnce,
			TouchPolicy: piv.TouchPolicyAlways,
		})
		if err != nil {
			log.Fatalf("Failed to generate key for %s slot: %v", slotName, err)
		}

		pubKey = pub

		var priv interface{}
		var parentPub crypto.PublicKey
		switch algo {
		case "ecp256":
			priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			parentPub = priv.(*ecdsa.PrivateKey).Public()
		case "ecp384":
			priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			parentPub = priv.(*ecdsa.PrivateKey).Public()
		case "rsa2048":
			priv, err = rsa.GenerateKey(rand.Reader, 2048)
			parentPub = priv.(*rsa.PrivateKey).Public()
		case "rsa3072":
			priv, err = rsa.GenerateKey(rand.Reader, 3072)
			parentPub = priv.(*rsa.PrivateKey).Public()
		case "rsa4096":
			priv, err = rsa.GenerateKey(rand.Reader, 4096)
			parentPub = priv.(*rsa.PrivateKey).Public()
		case "ed25519":
			_, priv, err = ed25519.GenerateKey(rand.Reader)
			parentPub = priv.(ed25519.PrivateKey).Public()
		case "x25519":
			//priv, err = x25519.GenerateKey(rand.Reader)
			//parentPub = priv.Public()
			log.Fatalf("x25519 not supported yet!")
		}
		if err != nil {
			log.Fatalf("Failed to generate parent key for %s slot: %v", slotName, err)
		}

		parent := &x509.Certificate{
			Subject: pkix.Name{
				Organization:       []string{"yubikey-agent"},
				OrganizationalUnit: []string{Version},
			},
			PublicKey: parentPub,
		}
		template := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: fmt.Sprintf("SSH key (%s)", slotName),
			},
			NotAfter:     time.Now().AddDate(42, 0, 0),
			NotBefore:    time.Now(),
			SerialNumber: randomSerialNumber(),
			KeyUsage:     x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
		}
		certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, priv)
		if err != nil {
			log.Fatalf("Failed to generate certificate for %s slot: %v", slotName, err)
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			log.Fatalf("Failed to parse certificate for %s slot: %v", slotName, err)
		}
		if err := yk.SetCertificate(key, slot, cert); err != nil {
			log.Fatalf("Failed to store certificate for %s slot: %v", slotName, err)
		}

		sshKey, err := ssh.NewPublicKey(pubKey)
		if err != nil {
			log.Fatalf("Failed to generate public key for %s slot: %v", slotName, err)
		}

		fmt.Printf("\n🔑 Here's your new shiny SSH public key for %s slot:\n", slotName)
		os.Stdout.Write(ssh.MarshalAuthorizedKey(sshKey))
	}

	// Generate keys and certificates for both Authentication and Key Management slots
	generateKeyAndCert(piv.SlotAuthentication, "Authentication (9a)")
	generateKeyAndCert(piv.SlotSignature, "Digital Signature (9c)")

	fmt.Println("")
	fmt.Println("✅ Done! This YubiKey is secured and ready to go.")
	fmt.Println("🤏 When the YubiKey blinks, touch it to authorize the login.")
	fmt.Println("")
	fmt.Println("Next steps: ensure yubikey-agent is running via launchd/systemd/...,")
	fmt.Printf("set the SSH_AUTH_SOCK environment variable, and test with \"ssh-add -L\"\n")
	fmt.Println("")
	fmt.Println("💭 Remember: everything breaks, have a backup plan for when this YubiKey does.")
}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalln("Failed to generate serial number:", err)
	}
	return serialNumber
}
