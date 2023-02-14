package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	name := flag.String("name", "", "The name for the certificate that will be displayed in the Sophos Webinterface")
	username := flag.String("username", "", "Username for authentication")
	password := flag.String("password", "", "Password for authentication")
	certFilePath := flag.String("cert", "", "Path to certificate file")
	keyFilePath := flag.String("key", "", "Path to key file")
	ip := flag.String("ip", "", "Ipv4 address from the sophos firewall")
	port := flag.Uint("port", 4444, "The port for the sophos firewall")
	flag.Parse()

	certFile, err := os.Open(*certFilePath)
	defer certFile.Close()
	if err != nil {
		log.Fatal(err)
	}
	certFileName := filepath.Base(*certFilePath)

	keyFile, err := os.Open(*keyFilePath)
	defer keyFile.Close()
	if err != nil {
		log.Fatal(err)
	}
	keyFileName := filepath.Base(*keyFilePath)

	payload := &bytes.Buffer{}
	multipartWriter := multipart.NewWriter(payload)

	certWriter, err := multipartWriter.CreateFormFile("Certificate", certFileName)
	if err != nil {
		log.Fatal(err)
	}
	_, err = io.Copy(certWriter, certFile)
	if err != nil {
		log.Fatal(err)
	}

	keyWriter, err := multipartWriter.CreateFormFile("Private Key", keyFileName)
	if err != nil {
		log.Fatal(err)
	}
	_, err = io.Copy(keyWriter, keyFile)
	if err != nil {
		log.Fatal(err)
	}

	reqStr := fmt.Sprintf(`<Request><Login><Username>%s</Username><Password>%s</Password></Login><Set><Certificate transactionid="10"><Name>%s</Name><Action>UploadCertificate</Action><CertificateFormat>pem</CertificateFormat><CertificateFile>%s</CertificateFile><PrivateKeyFile>%s</PrivateKeyFile></Certificate></Set></Request>`, *username, *password, *name, certFileName, keyFileName)
	err = multipartWriter.WriteField("reqxml", reqStr)
	if err != nil {
		log.Fatal(err)
	}
	err = multipartWriter.Close()
	if err != nil {
		log.Fatal(err)
	}

	url := fmt.Sprintf("https://%s:%d/webconsole/APIController", *ip, *port)
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	req, err := http.NewRequest("GET", url, payload)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(body))
}
