// Copyright 2015 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awsutil"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"

	"golang.org/x/crypto/acme"
)

var (
	cmdCert = &command{
		run:       runCert,
		UsageLine: "cert [-c config] [-d url] [-s host:port] [-k key] [-expiry dur] [-bundle=true] [-manual=false] [-dns=false] [-s3=false] [-tls=false] [-s3bucket=bucket] domain [domain ...]",
		Short:     "request a new certificate",
		Long: `
Cert creates a new certificate for the given domain.
It uses the http-01 challenge type by default and dns-01 if -dns is specified.

The certificate will be placed alongside key file, specified with -k argument.
If the key file does not exist, a new one will be created.
Default location for the key file is {{.ConfigDir}}/domain.key,
where domain is the actually domain name provided as the command argument.

By default the obtained certificate will also contain the CA chain.
If this is undesired, specify -bundle=false argument.

The -s argument specifies the address where to run local server
for the http-01 challenge. If not specified, 127.0.0.1:8080 will be used.

An alternative to local server challenge response may be specified with -manual or -dns,
in which case instructions are displayed on the standard output.

Default location of the config dir is
{{.ConfigDir}}.
		`,
	}

	certDisco   = defaultDiscoFlag
	certAddr    = "127.0.0.1:8080"
	certExpiry  = 365 * 12 * time.Hour
	certBundle  = true
	certManual  = false
	certDNS     = false
	certS3      = false
	certTLS     = false
	certKeypath string
	s3bucket    string
)

func init() {
	cmdCert.flag.Var(&certDisco, "d", "")
	cmdCert.flag.StringVar(&certAddr, "s", certAddr, "")
	cmdCert.flag.DurationVar(&certExpiry, "expiry", certExpiry, "")
	cmdCert.flag.BoolVar(&certBundle, "bundle", certBundle, "")
	cmdCert.flag.BoolVar(&certManual, "manual", certManual, "")
	cmdCert.flag.BoolVar(&certDNS, "dns", certDNS, "")
	cmdCert.flag.BoolVar(&certS3, "s3", certS3, "")
	cmdCert.flag.BoolVar(&certTLS, "tls", certTLS, "")
	cmdCert.flag.StringVar(&certKeypath, "k", "", "")
	cmdCert.flag.StringVar(&s3bucket, "s3bucket", s3bucket, "")
}

func s3upload(file string) (string, error) {
	/*
		token := ""
		creds := credentials.NewStaticCredentials(aws_access_key_id, aws_secret_access_key, token)
		_, err := creds.Get()
		if err != nil {
			fmt.Printf("bad credentials: %s", err)
		}
	*/
	cfg := aws.NewConfig().WithRegion("us-east-1").WithCredentials(credentials.AnonymousCredentials)
	svc := s3.New(session.New(), cfg)

	uploadFile, err := os.Open(file)
	if err != nil {
		fmt.Printf("err opening file: %s", err)
	}
	defer uploadFile.Close()
	fileInfo, _ := uploadFile.Stat()
	size := fileInfo.Size()
	buffer := make([]byte, size) // read file content to buffer

	uploadFile.Read(buffer)
	fileBytes := bytes.NewReader(buffer)
	fileType := http.DetectContentType(buffer)
	path := "/.well-known/acme-challenge/" + filepath.Base(uploadFile.Name())
	fmt.Printf("file to upload: %s", path)
	params := &s3.PutObjectInput{
		Bucket:        aws.String(s3bucket),
		Key:           aws.String(path),
		Body:          fileBytes,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String(fileType),
	}
	resp, err := svc.PutObject(params)
	if err != nil {
		fmt.Printf("bad response: %s", err)
	}
	fmt.Printf("response %s", awsutil.StringValue(resp))
	return awsutil.StringValue(resp), err
}

func runCert(args []string) {
	if len(args) == 0 {
		fatalf("no domain specified")
	}
	if certManual && certDNS {
		fatalf("-dns and -manual are mutually exclusive, only one should be specified")
	}
	cn := args[0]
	if certKeypath == "" {
		certKeypath = filepath.Join(configDir, cn+".key")
	}

	// get user config
	uc, err := readConfig()
	if err != nil {
		fatalf("read config: %v", err)
	}
	if uc.key == nil {
		fatalf("no key found for %s", uc.URI)
	}

	// read or generate new cert key
	certKey, err := anyKey(certKeypath, true)
	if err != nil {
		fatalf("cert key: %v", err)
	}
	// generate CSR now to fail early in case of an error
	req := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	if len(args) > 1 {
		req.DNSNames = args
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, certKey)
	if err != nil {
		fatalf("csr: %v", err)
	}

	// initialize acme client and start authz flow
	// we only look for http-01 challenges at the moment
	client := &acme.Client{
		Key:          uc.key,
		DirectoryURL: string(certDisco),
	}
	for _, domain := range args {
		ctx, cancel := context.Background(), func() {}
		if !certManual && !certDNS {
			ctx, cancel = context.WithTimeout(context.Background(), 10*time.Minute)
		}
		if err := authz(ctx, client, domain); err != nil {
			fatalf("%s: %v", domain, err)
		}
		cancel()
	}

	// challenge fulfilled: get the cert
	// wait at most 30 min
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	cert, curl, err := client.CreateCert(ctx, csr, certExpiry, certBundle)
	if err != nil {
		fatalf("cert: %v", err)
	}
	logf("cert url: %s", curl)

	certPath := sameDir(certKeypath, cn+".crt")
	err = writeCert(certPath, cert)
	if err != nil {
		fatalf("write cert: %v", err)
	}
}

func authz(ctx context.Context, client *acme.Client, domain string) error {
	z, err := client.Authorize(ctx, domain)
	if err != nil {
		return err
	}
	if z.Status == acme.StatusValid {
		return nil
	}
	var chal *acme.Challenge
	for _, c := range z.Challenges {
		fmt.Printf("Challenge is: %s\n", c.Type)
		if (c.Type == "http-01" && !certDNS && !certTLS) || (c.Type == "dns-01" && certDNS) || (c.Type == "tls-sni-01" && certTLS) {
			chal = c
			break
		}
	}
	if chal == nil {
		return errors.New("no supported challenge found")
	}

	switch {
	case certManual:
		// manual challenge response
		tok, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		filename := client.HTTP01ChallengePath(chal.Token)
		file, err := challengeFile(domain, tok, filename)
		if err != nil {
			return err
		}
		fmt.Printf("Copy %s to http://%s%s and press enter.\n",
			file, domain, filename)
		var x string
		fmt.Scanln(&x)
	case certDNS:
		val, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return err
		}
		fmt.Printf("Add a TXT record for _acme-challenge.%s with the value %q and press enter after it has propagated.\n",
			domain, val)
		var x string
		fmt.Scanln(&x)
	case certS3:
		// Copy to S3 bucket which is hosting the website
		tok, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		webPath := client.HTTP01ChallengePath(chal.Token)
		file, err := challengeFile(domain, tok, webPath)
		if err != nil {
			return err
		}

		_, err = s3upload(file)
		if err != nil {
			return err
		}
	case certTLS:
		// TLS-SNI-01 challenge as Let's Encrypt doesn't support yet - 05-10-2017 TLS-SNI-02
		cert, certDNSNameA, err := client.TLSSNI01ChallengeCert(chal.Token)
		if err != nil {
			return fmt.Errorf("TLS-SNI-01 auth failed: %s", err)
		}
		certKey := cert.PrivateKey
		pk := certKey.(*ecdsa.PrivateKey)
		err = writeKey(configDir+"lets-encrypt-self-sign.key", pk)
		if err != nil {
			return fmt.Errorf("Unable to to write private key file %v", err)
		}

		err = writeCert(configDir+"lets-encrypt-self-sign.crt", cert.Certificate)
		if err != nil {
			return fmt.Errorf("Unable to to write certificate key file %v", err)
		}

		fmt.Printf("Certificate CommonName is: %s\n", certDNSNameA)
		cmd := exec.Command("service", "nginx", "restart")
		err = cmd.Run()
		if err != nil {
			log.Fatal(err)
		}
	default:
		// respond to http-01 challenge
		ln, err := net.Listen("tcp", certAddr)
		if err != nil {
			return fmt.Errorf("listen %s: %v", certAddr, err)
		}
		defer ln.Close()

		// auto, via local server
		val, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		path := client.HTTP01ChallengePath(chal.Token)
		go http.Serve(ln, http01Handler(path, val))

	}

	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept challenge: %v", err)
	}
	_, err = client.WaitAuthorization(ctx, z.URI)
	return err
}

func challengeFile(domain, content string, file string) (string, error) {
	dir, err := ioutil.TempDir("", "acme")
	if err != nil {
		log.Fatal(err)
	}
	tmpfn := filepath.Join(dir, filepath.Base(file))
	fileData := []byte(content)
	if err := ioutil.WriteFile(tmpfn, fileData, 0644); err != nil {
		log.Fatal(err)
	}
	return tmpfn, err
}

func http01Handler(path, value string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			log.Printf("unknown request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte(value))
	})
}
