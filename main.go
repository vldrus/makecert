package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

type stringArray []string

func (i *stringArray) String() string {
	return strings.Join(*i, ", ")
}

func (i *stringArray) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	var ctype string
	flag.StringVar(&ctype, "type", "rsa", "Certificate type, \"rsa\" or \"ec\"")

	var name string
	flag.StringVar(&name, "name", "App", "Common name for certificate")

	var years int
	flag.IntVar(&years, "years", 100, "Certificate validity period")

	var dnss stringArray
	flag.Var(&dnss, "dns", "DNS name for certificate")

	var ips stringArray
	flag.Var(&ips, "ip", "IP address for certificate")

	flag.Parse()

	before := time.Now()
	after := before.AddDate(100, 0, 0)

	fmt.Println("Generating self-signed certificate:")
	fmt.Println(" - From:        ", before.Format(time.UnixDate))
	fmt.Println(" - To:          ", after.Format(time.UnixDate))
	fmt.Println(" - Type:        ", strings.ToUpper(ctype))
	fmt.Println(" - Common name: ", name)
	fmt.Println(" - DNS names:   ", dnss)
	fmt.Println(" - IP addresses:", ips)

	var pkey crypto.Signer
	var err error

	ctype = strings.ToLower(ctype)

	switch ctype {
	case "ec":
		pkey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		pkey, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		err = fmt.Errorf("unknown type")
	}
	if err != nil {
		exitWithError("Cannot generate certificate key", err)
	}

	var cips []net.IP
	for _, ip := range ips {
		cip := net.ParseIP(ip)
		if cip == nil {
			fmt.Println("Note:", ip, "is not valid IP address")
			continue
		}
		cips = append(cips, cip)
	}

	cert := x509.Certificate{
		SerialNumber: big.NewInt(before.Unix()),
		Issuer:       pkix.Name{CommonName: name},
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    before,
		NotAfter:     after,
		DNSNames:     dnss,
		IPAddresses:  cips,
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}

	buf, err := x509.CreateCertificate(rand.Reader, &cert, &cert, pkey.Public(), pkey)
	if err != nil {
		exitWithError("Cannot generate certificate", err)
	}
	crt, err := os.Create("cert.crt")
	if err != nil {
		exitWithError("Cannot create file 'cert.crt'", err)
	}
	err = pem.Encode(crt, &pem.Block{Type: "CERTIFICATE", Bytes: buf})
	if err != nil {
		exitWithError("Cannot save certificate", err)
	}

	buf, err = x509.MarshalPKCS8PrivateKey(pkey)
	if err != nil {
		exitWithError("Cannot generate private key", err)
	}
	key, err := os.Create("cert.key")
	if err != nil {
		exitWithError("Cannot create file 'cert.key'", err)
	}
	err = pem.Encode(key, &pem.Block{Type: "PRIVATE KEY", Bytes: buf})
	if err != nil {
		exitWithError("Cannot save private key", err)
	}

	fmt.Println("Done. Certificate saved to 'cert.crt' and 'cert.key'.")
}

func exitWithError(msg string, err error) {
	fmt.Fprintln(os.Stderr, msg, "-", err)
	fmt.Fprintln(os.Stderr, "Exiting now.")
	os.Exit(1)
}
