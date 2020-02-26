package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"log"
	"os"
	"strings"
	"fmt"

	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/challenge/dns01"
	"github.com/go-acme/lego/registration"
	"github.com/mattheys/GoCCert/dnsprovidercpaneldns"
	"github.com/xenolf/lego/lego"
)

var (
	email       *string
	tos         *bool
	url         *string
	username    *string
	password    *string
	certdomains arrayFlags
	staging     *bool
	output      *string
	dnsservers  arrayFlags
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var version, commit string

func init() {
	email = flag.String("email", "", "Your email address")
	tos = flag.Bool("tos", false, "Do you agree to Let's Encrypts TOS")
	url = flag.String("url", "", "cPanel url including /json-api/cpanel")
	username = flag.String("username", "", "cPanel username")
	password = flag.String("password", "", "cPanel password")
	flag.Var(&certdomains, "certdomains", "Domain names you want a cert for")
	flag.Var(&dnsservers, "dnsservers", "List of DNS Servers you would like to use, ommiting this will use system wide dns server")
	staging = flag.Bool("staging", false, "Run in the staging environment?")
	output = flag.String("output", "", "Output filename, defaults to the first domainname.cert")

	flag.Parse()
	if certdomains == nil || *tos == false {
		fmt.Printf("GoCCert version %s, git commit %s\n\n",version,commit)
		flag.Usage()
		log.Fatal("Please supply all params")
	}

	if *tos == false {
		fmt.Printf("GoCCert version %s, git commit %s\n\n",version,commit)
		flag.Usage()
		log.Fatal("You must agree to the Terms of Service ")
	}

}

func main() {

	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	regUser := RegistrationUser{
		Email: *email,
		key:   privateKey,
	}

	config := lego.NewConfig(&regUser)

	if *staging {
		config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}

	config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	factory := *dnsprovidercpaneldns.NewCpanelFactory(*url, *username, *password)

	bestDNS, err := dnsprovidercpaneldns.NewDNSProviderCpanelDNS(factory)
	if err != nil {
		log.Fatal(err)
	}

	if len(dnsservers) > 0 {
		client.Challenge.SetDNS01Provider(bestDNS, dns01.AddRecursiveNameservers(dnsservers))
	} else {
		client.Challenge.SetDNS01Provider(bestDNS)
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	regUser.Registration = reg

	request := certificate.ObtainRequest{
		Domains: certdomains,
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	if *output == "" {
		*output = strings.Replace(certdomains[0], "*", "_", -1) + ".cert"
	}

	file, fileErr := os.Create(*output)
	if fileErr == nil {
		defer file.Close()
		file.Write(certificates.PrivateKey)
		file.Write(certificates.Certificate)
	}
}
