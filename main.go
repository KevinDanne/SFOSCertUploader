package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

const xmlRequestFormat string = `<Request><Login><Username>%s</Username><Password>%s</Password></Login><Set><Certificate transactionid="10"><Name>%s</Name><Action>UploadCertificate</Action><CertificateFormat>pem</CertificateFormat><CertificateFile>%s</CertificateFile><PrivateKeyFile>%s</PrivateKeyFile></Certificate></Set></Request>`

func PrintUsage() {
	fmt.Printf("%s <ip:port> <username> <password> <name> <cert path> <key path>\n", os.Args[0])
}

func writeMultipartFormFile(multipartWriter *multipart.Writer, fieldName, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	fileName := filepath.Base(filePath)
	fileWriter, err := multipartWriter.CreateFormFile(fieldName, fileName)
	if err != nil {
		return err
	}
	_, err = io.Copy(fileWriter, file)
	if err != nil {
		return err
	}
	return nil
}

func buildPayload(username, password, name, certFilePath, keyFilePath string) (*bytes.Buffer, string, error) {
	payload := &bytes.Buffer{}
	multipartWriter := multipart.NewWriter(payload)

	err := writeMultipartFormFile(multipartWriter, "Certificate", certFilePath)
	if err != nil {
		return nil, "", err
	}

	err = writeMultipartFormFile(multipartWriter, "Private Key", keyFilePath)
	if err != nil {
		return nil, "", err
	}

	reqXml := fmt.Sprintf(xmlRequestFormat, username, password, name, filepath.Base(certFilePath), filepath.Base(keyFilePath))
	err = multipartWriter.WriteField("reqxml", reqXml)
	if err != nil {
		return nil, "", err
	}
	err = multipartWriter.Close()
	if err != nil {
		return nil, "", err
	}

	return payload, multipartWriter.FormDataContentType(), nil
}

func sendAPIRequest(url, contentType string, payload io.Reader) (*http.Response, error) {
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	req, err := http.NewRequest("GET", url, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)

	return client.Do(req)
}

func main() {
	if len(os.Args) != 7 {
		PrintUsage()
		os.Exit(1)
	}
	args := os.Args[1:]
	address := args[0]
	username := args[1]
	password := args[2]
	name := args[3]
	certFilePath := args[4]
	keyFilePath := args[5]

	payload, contentType, err := buildPayload(username, password, name, certFilePath, keyFilePath)
	if err != nil {
		log.Fatal("Error while building payload: " + err.Error())
	}

	url := fmt.Sprintf("https://%s/webconsole/APIController", address)
	res, err := sendAPIRequest(url, contentType, payload)
	if err != nil {
		log.Fatal("Error while sending api request: " + err.Error())
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal("Error while parsing response Body: " + err.Error())
	}
	fmt.Printf("Response:\n%s", body)
}
