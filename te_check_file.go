package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"time"

	"github.com/Jeffail/gabs"
	"github.com/h2non/filetype"
	"github.com/utahta/go-openuri"
)

// remove first char, respect Unicode - https://play.golang.org/p/t93M8keTQP_I
// https://stackoverflow.com/questions/48798588/how-do-you-remove-the-first-character-of-a-string
func trimLeftChar(s string) string {
	for i := range s {
		if i > 0 {
			return s[i:]
		}
	}
	return s[:0]
}

// file type

func fileType(path string) {
	file, err := openuri.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	head := make([]byte, 261)
	file.Read(head)
	kind, _ := filetype.Match(head)
	if kind == filetype.Unknown {
		fmt.Println("Unknown file type")
		return
	}

	fmt.Printf("File type: %s. MIME: %s\n", kind.Extension, kind.MIME.Value)
}

// calculate SHA1 of the file
func fileSha1(path string) (string, error) {

	file, err := openuri.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha1.New()
	if _, err := io.Copy(hash, file); err != nil {
		log.Fatal(err)
	}
	sum := hash.Sum(nil)

	return hex.EncodeToString(sum), err
}

// create JSON payload with file details
func apiRequestPayload(file string, images []string) (string, error) {

	type JsonObject map[string]interface{}

	sha1, err := fileSha1(file)
	if err != nil {
		fmt.Println("Error calculating file SHA1")
		return "", err
	}

	imageList := []JsonObject{}

	for _, imageId := range images {
		// fmt.Println("request imageid", imageId)
		imageList = append(imageList, JsonObject{"id": imageId, "revision": 1})
	}

	// fmt.Println(imageList)

	request := JsonObject{
		"request": []JsonObject{
			{
				"sha1":      sha1,
				"file_type": trimLeftChar(filepath.Ext(file)),
				"file_name": filepath.Base(file),
				"features":  []string{"te"},
				"te": JsonObject{
					"reports": []string{
						"pdf",
						"xml",
						"tar",
						"full_report",
						"summary",
					},
					"images":                 imageList,
					"reports_version_number": 2,
				},
			},
		},
	}

	str, err := json.Marshal(request)
	if err != nil {
		fmt.Println("Error encoding JSON")
		return "", err
	}

	return string(str), err
}

// create multi-part request with instructions and file
func newfileUploadRequest(reqPayload string, path string, apiKey string, host string, port int) (*http.Request, error) {
	file, err := openuri.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(part, file)

	_ = writer.WriteField("request", reqPayload)

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s:%d/tecloud/api/v1/file/upload", host, port), body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", apiKey)
	return req, err
}

// process reports
/*
"te": {
        "trust": 10,
        "images": [
          {
            "report": {
              "verdict": "malicious",
              "full_report": "aaa892ad-58d5-4866-8bee-ee13179802ae",
              "pdf_report": "ce7fdf86-6501-43f5-a774-3e9c60764e5b",
              "xml_report": "b9a13ea2-28a4-43d5-a5a5-85e26441428d"
            },
            "status": "found",
            "id": "5e5de275-a103-4f67-b55b-47532918fa59",
            "revision": 1
          },
          {
            "report": {
              "verdict": "malicious",
              "full_report": "f30c3824-e156-4bad-8270-edb8b11a5979",
              "pdf_report": "61cfd184-7579-4715-8fd9-fd536c80c2db",
              "xml_report": "a9dc01d5-8fdc-40ad-9f43-a429b55996f1"
            },
            "status": "found",
            "id": "e50e99f3-5963-4573-af9e-e3f4750b55e2",
            "revision": 1
          }
		],
*/

type Report struct {
	imageId    string
	reportType string
	reportId   string
}

func processImages(imagesJson interface{}) []Report {
	// fmt.Println("images", imagesJson)

	reportsList := []Report{}

	for _, image := range imagesJson.([]interface{}) {
		imageObj := image.(map[string]interface{})
		reports := imageObj["report"].(map[string]interface{})
		// fmt.Println("image: ", image, imageObj["report"], reports)
		for key, value := range reports {
			if key != "verdict" {
				report := Report{imageId: imageObj["id"].(string), reportType: key, reportId: value.(string)}
				reportsList = append(reportsList, report)
				// fmt.Println("\t", report)
			}
		}
	}
	return reportsList
}

// determine status code
func processResponse(resp []byte) (float64, []Report) {

	jsonParsed, err := gabs.ParseJSON(resp)
	if err != nil {
		panic(err)
	}

	summaryReport, hasSummaryReport := jsonParsed.Path("response.te.summary_report").Data().(string)
	if !hasSummaryReport {
		summaryReport, hasSummaryReport = jsonParsed.Path("response.0.te.summary_report").Data().(string)
	}

	//fmt.Println("one", jsonParsed.Path("response"), jsonParsed.Path("response.te.summary_report"))
	//fmt.Println("arr", jsonParsed.Path("response.0"), jsonParsed.Path("response.0.te.summary_report"))

	var m map[string]interface{}
	err = json.Unmarshal(resp, &m)
	if err != nil {
		fmt.Println("JSON parsing failed - invalid response JSON format")
		return -1, []Report{}
	}

	var response map[string]interface{}

	// query response comes as array, upload response is just one
	responseArray, ok0 := m["response"].([]interface{})
	if ok0 {
		response = responseArray[0].(map[string]interface{})
	} else {
		singleResponse, ok1 := m["response"].(map[string]interface{})
		if !ok1 {
			fmt.Println(`JSON parsing failed - m["response"]`)
			return -1, []Report{}
		}
		response = singleResponse
	}

	// response has status section
	status, ok2 := response["status"].(map[string]interface{})
	if !ok2 {
		fmt.Println(`JSON parsing failed - response["status"]`)
		return -1, []Report{}
	}

	// status section has code. JSON decoded it as float64
	statusCode, ok3 := status["code"].(float64)
	if !ok3 {
		fmt.Println(`JSON parsing failed -  status["code"]`)
		return -1, []Report{}
	}

	//fmt.Println("TE response", response["te"]);
	teResponse, okTeResponse := response["te"].(map[string]interface{})
	if okTeResponse {
		reportList := processImages(teResponse["images"])

		if hasSummaryReport && len(summaryReport) > 0 {
			// fmt.Println("SUMMARY report", summaryReport)
			reportList = append(reportList, Report{imageId: "", reportType: "summary_report", reportId: summaryReport})
		}
		return statusCode, reportList
	}

	return statusCode, []Report{}
}

func doDownloadReport(reportId string, client *http.Client, apiKey string, host string, port int) *io.ReadCloser {

	url := fmt.Sprintf("https://%s:%d/tecloud/api/v1/file/download?id=%s", host, port, reportId)

	req, err := http.NewRequest("GET", url, nil)

	req.Header.Set("Authorization", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	for k, v := range resp.Header {
		if k == "Content-Disposition" || k == "Content-Type" {
			fmt.Printf("REP Header field %q, Value %q\n", k, v)
		}
	}

	//defer resp.Body.Close()

	// fmt.Println(resp.StatusCode, resp.Status)

	return &resp.Body
	// body, _ := ioutil.ReadAll(resp.Body)
	// return body
	// fmt.Println(string(body))

}

// do query request and return TE API status code
func doQuery(reqPayload string, client *http.Client, apiKey string, host string, port int) (float64, []Report) {

	url := fmt.Sprintf("https://%s:%d/tecloud/api/v1/file/query", host, port)

	var jsonStr = []byte(reqPayload)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))

	req.Header.Set("Authorization", apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// fmt.Println(resp.StatusCode, resp.Status)

	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))

	return processResponse(body)
}

// upload file and return TE API status code
func doUpload(reqPayload string, client *http.Client, file string, apiKey string, host string, port int) (float64, []Report) {

	request, err := newfileUploadRequest(reqPayload, file, apiKey, host, port)
	if err != nil {
		log.Fatal(err)
	}

	uploadResp, uploadErr := client.Do(request)
	if uploadErr != nil {
		log.Fatal(uploadErr)
	} else {
		body := &bytes.Buffer{}
		_, err := body.ReadFrom(uploadResp.Body)
		if err != nil {
			log.Fatal(err)
		}
		uploadResp.Body.Close()
		fmt.Println(body)

		return processResponse(body.Bytes())
	}

	return -1, []Report{}
}

var imageNameToImageId = map[string]string{
	"W_7_32":            "7e6fe36e-889e-4c25-8704-56378f0830df",
	"W_XP":              "e50e99f3-5963-4573-af9e-e3f4750b55e2",
	"W_7_32_Office2010": "8d188031-1010-4466-828b-0cd13d4303ff",
	"W_7_32_Office2013": "5e5de275-a103-4f67-b55b-47532918fa59",
	"W_7_64":            "3ff3ddae-e7fd-4969-818c-d5f1a2be336d",
	"W_10":              "10b4a9c6-e414-425c-ae8b-fe4dd7b25244",
	"W_8_1":             "6c453c9b-20f7-471a-956c-3198a868dc92",
	"MAC_OS_X":          "d2acf0d2-6d2e-4c2e-86b3-20a30ca6a3f6",
}

// check if string exists in array of strings
func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func main() {

	// path to file is required
	filePtr := flag.String("f", "", "File to check (Required)")
	apikeyPtr := flag.String("k", "", "cloud service API key")
	hostPtr := flag.String("h", "te.checkpoint.com", "appliance IP or hostname")
	portPtr := flag.Int("p", 443, "service port (e.g. 443 for cloud, 18194 for local TE)")
	insecurePtr := flag.Bool("insecure", false, "Ignore untrusted server cert")

	// images
	type ImageFlag *bool
	imageFlagsById := make(map[string]ImageFlag)
	for imageName, imageId := range imageNameToImageId {
		// fmt.Printf("image %s \t %s\n", imageId, imageName)

		imageFlagsById[imageId] = flag.Bool(imageName, contains([]string{"W_7_32", "W_XP"}, imageName), fmt.Sprintf("enable image %s", imageName))

	}

	// fmt.Println(imageFlagsById)
	flag.Parse()

	apiKey := ""
	if *apikeyPtr != "" {
		apiKey = *apikeyPtr
	} else {
		apiKey = os.Getenv("TE_API_KEY")
		if apiKey == "" {
			apiKey = "TE_API_KEY_4wqjsmFM7TufVe4jW3KurHEDxveJrpOXV3zwOtf9"
		}
	}

	// print usage when no file specified
	if *filePtr == "" {
		exePath, _ := os.Executable()
		fmt.Println("Usage:", filepath.Base(exePath))
		flag.PrintDefaults()
		os.Exit(1)
	}

	// fileType(*filePtr)

	enabledImages := []string{}
	for imageId, imageFlagPtr := range imageFlagsById {
		if *imageFlagPtr {
			enabledImages = append(enabledImages, imageId)
		}
	}
	// fmt.Println("enabled images ", enabledImages)

	// get API request with file details
	reqPayload, err := apiRequestPayload(*filePtr, enabledImages)
	if err != nil {
		fmt.Println("Error building API request")
		os.Exit(2)
	}
	// fmt.Printf("reqPayload %s\n", reqPayload)

	// cookies - to help loadbalancers to reach our server
	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		panic(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	var client *http.Client

	if *insecurePtr {
		// keep client to share cookie for load-balancer
		client = &http.Client{Jar: jar, Transport: tr}
	} else {
		client = &http.Client{Jar: jar}
	}

	var statusCode, reports = doQuery(reqPayload, client, apiKey, *hostPtr, *portPtr)

	for statusCode != 1001 {

		switch statusCode {
		case 1004, 1006: // NOT_FOUND, PARTIALLY_FOUND
			// server is missing file, upload it
			statusCode, reports = doUpload(reqPayload, client, *filePtr, apiKey, *hostPtr, *portPtr)

		case 1003, 1002: // PENDING, UPLOAD_SUCCESS
			// server is working on it or will start soon
			time.Sleep(30 * time.Second)
			statusCode, reports = doQuery(reqPayload, client, apiKey, *hostPtr, *portPtr)

		case -1: // ERROR
			fmt.Println("Error processing request")
			os.Exit(3)
		}

	}

	// fmt.Println(reports)

	for _, r := range reports {

		fmt.Println("report", r)
		reportReaderPtr := doDownloadReport(r.reportId, client, apiKey, *hostPtr, *portPtr)
		defer (*reportReaderPtr).Close()
		var reportReader io.Reader = *reportReaderPtr

		reportFileextension := "base64"
		switch r.reportType {
		case "pdf_report":
			reportFileextension = "pdf"
		case "xml_report":
			reportFileextension = "xml"
			/* 		case "summary_report", "full_report":
			reportReader = base64.NewDecoder(base64.StdEncoding, reportReader)
			reportFileextension = "tgz"
			*/
		}
		reportFilename := fmt.Sprintf("%s-%s-%s.%s", r.reportType, r.imageId, r.reportId, reportFileextension)

		reportBody, err := ioutil.ReadAll(reportReader)
		if err != nil {
			fmt.Println(err)
		}
		err = ioutil.WriteFile(reportFilename, reportBody, 0666)
		check(err)
		fmt.Println("Saved report to ", reportFilename)
	}
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

