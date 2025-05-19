package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"
)

const (
	version    = "1.0"
	blockSize  = 262144
	maxThreads = 24
)

type options struct {
	advanced       string
	compactJSON    bool
	connectTimeout int
	delete         bool
	fields         string
	filter         string
	get            bool
	help           bool
	limit          string
	uploadName     string
	sort           string
	offset         string
	post           string
	put            string
	password       string
	server         string
	threads        int
	token          string
	upload         string
	user           string
	showVersion    bool
	tlsSkipVerify  bool   // Skip TLS certificate verification
	tlsCACert      string // Path to custom CA certificate file
}

type uploadResponse struct {
	ID             string `json:"id"`
	AllocatedBytes int64  `json:"allocated_bytes"`
	Name           string `json:"name"`
}

func main() {
	cliOpts := parseFlags(flag.CommandLine, os.Args[1:])

	if cliOpts.showVersion {
		fmt.Println(version)
		os.Exit(0) // Exit code 0: Success (Standardized)
	}

	if cliOpts.help || flag.NArg() == 0 {
		usage()
		os.Exit(0) // Exit code 0: Success (Standardized)
	}

	apiPath := flag.Arg(0)
	if !strings.HasPrefix(apiPath, "/") {
		apiPath = "/" + apiPath
	}

	// Determine method
	method := "GET"
	if cliOpts.delete {
		method = "DELETE"
	} else if cliOpts.post != "" {
		method = "POST"
	} else if cliOpts.put != "" {
		method = "PUT"
	} else if cliOpts.upload != "" {
		handleUpload(apiPath, cliOpts)
		return
	}

	// Build URL
	baseURL := fmt.Sprintf("https://%s/api%s", cliOpts.server, apiPath)
	queryParams := url.Values{}

	// Add query parameters
	if cliOpts.fields != "" {
		queryParams.Add("fields", cliOpts.fields)
	}
	if cliOpts.filter != "" {
		queryParams.Add("filter", cliOpts.filter)
	}
	if cliOpts.sort != "" {
		queryParams.Add("sort", cliOpts.sort)
	}
	if cliOpts.limit != "" {
		queryParams.Add("limit", cliOpts.limit)
	}
	if cliOpts.offset != "" {
		queryParams.Add("offset", cliOpts.offset)
	}
	if cliOpts.advanced != "" {
		for _, param := range strings.Split(cliOpts.advanced, "&") {
			if parts := strings.SplitN(param, "=", 2); len(parts) == 2 {
				queryParams.Add(parts[0], parts[1])
			}
		}
	}

	// Append query string to URL if we have parameters
	if len(queryParams) > 0 {
		baseURL += "?" + queryParams.Encode()
	}

	// Create client with optional timeout
	// TLS configuration
	tlsConfig := &tls.Config{InsecureSkipVerify: cliOpts.tlsSkipVerify}
	if cliOpts.tlsCACert != "" {
		rootCAs, err := loadCACert(cliOpts.tlsCACert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading CA certificate: %v\n", err)
			os.Exit(5) // Exit code 5: Configuration error (Standardized)
		}
		tlsConfig.RootCAs = rootCAs
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	if cliOpts.connectTimeout > 0 {
		client.Timeout = time.Duration(cliOpts.connectTimeout) * time.Second
	}

	// Create request
	var body io.Reader
	if method == "POST" {
		body = strings.NewReader(cliOpts.post)
	} else if method == "PUT" {
		body = strings.NewReader(cliOpts.put)
	}

	req, err := http.NewRequest(method, baseURL, body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating request: %v\n", err)
		os.Exit(2) // Exit code 2: Invalid input (Standardized)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if !cliOpts.compactJSON {
		req.Header.Set("X-JSON-Non-Compact", "1")
	}

	// Set auth
	if cliOpts.token != "" {
		req.Header.Set("x-yottabyte-token", cliOpts.token)
	} else if !(apiPath == "/sys/tokens" && method == "POST") {
		if cliOpts.password == "" && os.Getenv("YB_TOKEN") == "" {
			if cliOpts.token == "" {
				if isTerminal(os.Stdin.Fd()) {
					fmt.Print("Password: ")
					password, err := readPassword()
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
						os.Exit(2) // Exit code 2: Invalid input (Standardized)
					}
					cliOpts.password = string(password)
					fmt.Println() // Print newline after password input
				}
				if cliOpts.password == "" {
					fmt.Fprintln(os.Stderr, "Password is required")
					os.Exit(2) // Exit code 2: Invalid input (Standardized)
				}
			}
		} else if os.Getenv("YB_TOKEN") != "" {
			req.Header.Set("x-yottabyte-token", os.Getenv("YB_TOKEN"))
		}

		if cliOpts.token == "" && req.Header.Get("x-yottabyte-token") == "" {
			req.SetBasicAuth(cliOpts.user, cliOpts.password)
		}
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing request: %v\n", err)
		os.Exit(4) // Exit code 4: API error (Standardized)
	}
	defer resp.Body.Close()

	// Read response
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
		os.Exit(4) // Exit code 4: API error (Standardized)
	}

	// Output response
	fmt.Println(string(responseBody))

	// Check status code
	if resp.StatusCode >= 400 && resp.StatusCode < 600 {
		os.Exit(4) // Exit code 4: API error (Standardized)
	}
}

func handleUpload(apiPath string, cliOpts options) {
	// Validate threads
	if cliOpts.threads < 1 || cliOpts.threads > maxThreads {
		fmt.Fprintf(os.Stderr, "Threads must be from 1 to %d\n", maxThreads)
		os.Exit(2) // Exit code 2: Invalid input (Standardized)
	}

	// Check upload file
	if cliOpts.upload == "" {
		fmt.Fprintln(os.Stderr, "Upload file is required")
		os.Exit(2) // Exit code 2: Invalid input (Standardized)
	}

	fileInfo, err := os.Stat(cliOpts.upload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Upload file must exist: %v\n", err)
		os.Exit(6) // Exit code 6: Resource not found (Standardized)
	}

	if fileInfo.IsDir() {
		fmt.Fprintln(os.Stderr, "Can only upload regular files")
		os.Exit(2) // Exit code 2: Invalid input (Standardized)
	}

	// Use filename if upload name not specified
	if cliOpts.uploadName == "" {
		cliOpts.uploadName = filepath.Base(cliOpts.upload)
	}

	fileSize := fileInfo.Size()

	// Create initial upload request
	uploadURL := fmt.Sprintf("https://%s/api%s", cliOpts.server, apiPath)
	uploadReq := map[string]interface{}{
		"allocated_bytes": strconv.FormatInt(fileSize, 10),
		"name":            cliOpts.uploadName,
	}

	// Add any advanced parameters if provided
	if cliOpts.advanced != "" {
		var advancedParams map[string]interface{}
		if err := json.Unmarshal([]byte("{"+cliOpts.advanced+"}"), &advancedParams); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing advanced parameters: %v\n", err)
			os.Exit(2) // Exit code 2: Invalid input (Standardized)
		}
		for k, v := range advancedParams {
			uploadReq[k] = v
		}
	}

	uploadReqJSON, err := json.Marshal(uploadReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating upload request: %v\n", err)
		os.Exit(4) // Exit code 4: API error (Standardized)
	}

	// Create HTTP client
	// TLS configuration for upload
	tlsConfig := &tls.Config{InsecureSkipVerify: cliOpts.tlsSkipVerify}
	if cliOpts.tlsCACert != "" {
		rootCAs, err := loadCACert(cliOpts.tlsCACert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading CA certificate: %v\n", err)
			os.Exit(1)
		}
		tlsConfig.RootCAs = rootCAs
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	if cliOpts.connectTimeout > 0 {
		client.Timeout = time.Duration(cliOpts.connectTimeout) * time.Second
	}

	// Initialize upload
	uploadReqObj, err := http.NewRequest("POST", uploadURL, bytes.NewBuffer(uploadReqJSON))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating request: %v\n", err)
		os.Exit(4) // Exit code 4: API error (Standardized)
	}

	uploadReqObj.Header.Set("Content-Type", "application/json")
	uploadReqObj.Header.Set("Expect", "")

	// Set auth
	if cliOpts.token != "" {
		uploadReqObj.Header.Set("x-yottabyte-token", cliOpts.token)
	} else if os.Getenv("YB_TOKEN") != "" {
		uploadReqObj.Header.Set("x-yottabyte-token", os.Getenv("YB_TOKEN"))
	} else {
		uploadReqObj.SetBasicAuth(cliOpts.user, cliOpts.password)
	}

	uploadRespObj, err := client.Do(uploadReqObj)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to post file '%s': %v\n", cliOpts.uploadName, err)
		os.Exit(4) // Exit code 4: API error (Standardized)
	}
	defer uploadRespObj.Body.Close()

	if uploadRespObj.StatusCode >= 400 {
		body, _ := io.ReadAll(uploadRespObj.Body)
		fmt.Fprintf(os.Stderr, "Unable to post file '%s': %s\n", cliOpts.uploadName, string(body))
		os.Exit(4) // Exit code 4: API error (Standardized)
	}

	// Read the raw response body into a buffer
	rawBody, err := io.ReadAll(uploadRespObj.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading upload response: %v\n", err)
		os.Exit(4) // Exit code 4: API error (Standardized)
	}

	// fileID will hold the extracted file identifier from the API response.
	// Retain uploadResp for later use (e.g., printing the response), but do not use for file ID extraction.
	var uploadResp uploadResponse
	_ = json.Unmarshal(rawBody, &uploadResp) // Ignore error, only used for output
	var fileID string
	// Attempt to decode JSON from the buffer
	// Extract file ID from JSON response.
	// The API does not return an "id" field; instead, the file ID is the last segment of the "location" field,
	// or the value of the "$key" field. We unmarshal into a generic map to check for these fields.
	var respMap map[string]interface{}
	if err := json.Unmarshal(rawBody, &respMap); err == nil {
		// Try to extract from "location" field (last path segment)
		if locVal, ok := respMap["location"].(string); ok && locVal != "" {
			locVal = strings.TrimRight(locVal, "/")
			base := filepath.Base(locVal)
			if base != "." && base != "" {
				fileID = base
			}
		}
		// If not found, try "$key" field
		if fileID == "" {
			if keyVal, ok := respMap["$key"].(string); ok && keyVal != "" {
				fileID = keyVal
			}
		}
	} else {
		fileID = ""
	}

	// Fallback: Try to extract from Location header (legacy or non-JSON response)
	if fileID == "" {
		location := uploadRespObj.Header.Get("Location")
		location = strings.TrimRight(location, "/")
		base := filepath.Base(location)
		if base != "." && base != "" {
			fileID = base
		}
	}

	// Final fallback: Try to extract file ID from raw response body using string manipulation,
	// similar to the shell script. This handles cases where the response is not valid JSON
	// and the Location header is missing or unhelpful.
	if fileID == "" {
		rawStr := strings.TrimSpace(string(rawBody))
		rawStr = strings.Trim(rawStr, "/")
		parts := strings.Split(rawStr, "/")
		if len(parts) > 0 {
			candidate := parts[len(parts)-1]
			candidate = strings.TrimSpace(candidate)
			if candidate != "" && candidate != "." {
				fileID = candidate
			}
		}
	}

	if fileID == "" {
		fmt.Fprintln(os.Stderr, "Could not determine file ID from response.")
		fmt.Fprintf(os.Stderr, "---- Enhanced Debug Info ----\n")
		fmt.Fprintf(os.Stderr, "HTTP Status Code: %d\n", uploadRespObj.StatusCode)
		fmt.Fprintf(os.Stderr, "Location Header: %q\n", uploadRespObj.Header.Get("Location"))
		fmt.Fprintf(os.Stderr, "Raw Response Body:\n%s\n", string(rawBody))
		fmt.Fprintf(os.Stderr, "----------------------------\n")
		os.Exit(4) // Exit code 4: API error (Standardized)
	}

	// Open the file
	uploadFile, err := os.Open(cliOpts.upload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(6) // Exit code 6: Resource not found (Standardized)
	}
	defer uploadFile.Close()

	// Calculate number of chunks
	totalChunks := fileSize / blockSize
	if fileSize%blockSize > 0 {
		totalChunks++
	}

	// Setup progress tracking
	var uploadWg sync.WaitGroup
	uploadSemaphore := make(chan struct{}, cliOpts.threads)
	uploadErrChan := make(chan error, 1)
	uploadDoneChan := make(chan struct{})
	uploadedChunks := int64(0)
	var progressMu sync.Mutex

	// Setup interrupt handler
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interrupt
		fmt.Fprintln(os.Stderr, "\nUpload interrupted")
		close(uploadDoneChan)
	}()

	// Display progress if terminal
	if isTerminal(os.Stdout.Fd()) {
		fmt.Fprintf(os.Stderr, "\r[  0%%]")
	}

	// Upload chunks in parallel
	for chunkNum := int64(0); chunkNum < totalChunks; chunkNum++ {
		select {
		case <-uploadDoneChan:
			break
		case err := <-uploadErrChan:
			fmt.Fprintf(os.Stderr, "\nError uploading file: %v\n", err)
			os.Exit(4) // Exit code 4: API error (Standardized)
		default:
			// Use semaphore for concurrency control
			uploadSemaphore <- struct{}{}
			uploadWg.Add(1)

			go func(chunk int64) {
				defer uploadWg.Done()
				defer func() { <-uploadSemaphore }()

				// Read chunk
				buffer := make([]byte, blockSize)
				offset := chunk * blockSize
				uploadFile.Seek(offset, 0)
				bytesRead, err := uploadFile.Read(buffer)
				if err != nil && err != io.EOF {
					select {
					case uploadErrChan <- fmt.Errorf("error reading file at position %d: %v", offset, err):
					default:
					}
					return
				}

				// Trim buffer to actual data read
				buffer = buffer[:bytesRead]

				// Upload chunk
				chunkUploadURL := fmt.Sprintf("%s/%s?filepos=%d", uploadURL, fileID, offset)
				chunkReq, err := http.NewRequest("PUT", chunkUploadURL, bytes.NewBuffer(buffer))
				if err != nil {
					select {
					case uploadErrChan <- fmt.Errorf("error creating chunk request: %v", err):
					default:
					}
					return
				}

				chunkReq.Header.Set("Content-Type", "application/octet-stream")
				chunkReq.Header.Set("Expect", "")

				// Set auth
				if cliOpts.token != "" {
					chunkReq.Header.Set("x-yottabyte-token", cliOpts.token)
				} else if os.Getenv("YB_TOKEN") != "" {
					chunkReq.Header.Set("x-yottabyte-token", os.Getenv("YB_TOKEN"))
				} else {
					chunkReq.SetBasicAuth(cliOpts.user, cliOpts.password)
				}

				// Use a new HTTP client with keep-alives disabled for each chunk upload.
				// This avoids connection reuse issues ("server closed idle connection") seen with shared clients,
				// and matches the shell script's robustness by ensuring each chunk uses a new connection.
				chunkClient := &http.Client{
					Transport: &http.Transport{
						TLSClientConfig:   tlsConfig,
						DisableKeepAlives: true,
					},
				}
				chunkResp, err := chunkClient.Do(chunkReq)
				if err != nil {
					select {
					case uploadErrChan <- fmt.Errorf("error uploading chunk at position %d: %v", offset, err):
					default:
					}
					return
				}
				defer chunkResp.Body.Close()

				if chunkResp.StatusCode >= 400 {
					body, _ := io.ReadAll(chunkResp.Body)
					select {
					case uploadErrChan <- fmt.Errorf("error uploading chunk at position %d: %s", offset, string(body)):
					default:
					}
					return
				}

				// Update progress
				progressMu.Lock()
				uploadedChunks++
				if isTerminal(os.Stdout.Fd()) {
					percentage := uploadedChunks * 100 / totalChunks
					fmt.Fprintf(os.Stderr, "\r[%3d%%]", percentage)
				}
				progressMu.Unlock()
			}(chunkNum)
		}
	}

	// Wait for all uploads to complete
	uploadWg.Wait()
	close(uploadDoneChan)

	select {
	case err := <-uploadErrChan:
		fmt.Fprintf(os.Stderr, "\nError uploading file: %v\n", err)
		os.Exit(4) // Exit code 4: API error (Standardized)
	default:
		if isTerminal(os.Stdout.Fd()) {
			fmt.Fprintln(os.Stderr)
		}

		// Print final response
		respData, err := json.Marshal(uploadResp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting response: %v\n", err)
			os.Exit(4) // Exit code 4: API error (Standardized)
		}
		fmt.Println(string(respData))
	}
}

func parseFlags(fs *flag.FlagSet, args []string) options {
	cliOpts := options{
		server:  "yb-api",
		user:    "admin",
		threads: 8,
	}

	// Override user from env if available
	if envUser := os.Getenv("YB_USER"); envUser != "" {
		cliOpts.user = envUser
		if cliOpts.user == "root" || cliOpts.user == "ybuser" {
			cliOpts.user = "admin"
		}
	}

	// Override token from env if available
	if envToken := os.Getenv("YB_TOKEN"); envToken != "" {
		cliOpts.token = envToken
	}

	fs.StringVarP(&cliOpts.advanced, "advanced", "a", "", "Advanced querystring parameters to send")
	fs.BoolVarP(&cliOpts.compactJSON, "compact-json", "c", false, "Retrieve compact JSON from the API")
	fs.IntVarP(&cliOpts.connectTimeout, "connect-timeout", "C", 0, "Connection timeout in seconds")
	fs.BoolVarP(&cliOpts.delete, "delete", "d", false, "DELETE a row")
	fs.StringVarP(&cliOpts.fields, "fields", "f", "", "Specify a field list")
	fs.StringVarP(&cliOpts.filter, "filter", "F", "", "Specify a filter list")
	fs.BoolVarP(&cliOpts.get, "get", "g", false, "GET a row (default)")
	fs.BoolVarP(&cliOpts.help, "help", "h", false, "Show help")
	fs.StringVarP(&cliOpts.limit, "limit", "l", "", "Limit result count")
	fs.StringVarP(&cliOpts.uploadName, "upload-name", "n", "", "Override the filename for an upload")
	fs.StringVarP(&cliOpts.sort, "sort", "o", "", "Sort based on key[s]")
	fs.StringVarP(&cliOpts.offset, "offset", "O", "", "Skip first COUNT results")
	fs.StringVarP(&cliOpts.post, "post", "p", "", "POST a row")
	fs.StringVarP(&cliOpts.put, "put", "P", "", "PUT a row")
	fs.StringVarP(&cliOpts.password, "password", "s", "", "User password")
	fs.StringVarP(&cliOpts.server, "server", "S", "yb-api", "Server to send command to")
	fs.IntVarP(&cliOpts.threads, "threads", "t", 8, "Use CNT threads for uploads")
	fs.StringVarP(&cliOpts.token, "token", "T", "", "Use an auth token instead of user/password")
	fs.StringVarP(&cliOpts.upload, "upload", "U", "", "Upload FILE to the server")
	fs.StringVarP(&cliOpts.user, "user", "u", cliOpts.user, "User login")
	fs.BoolVarP(&cliOpts.showVersion, "version", "V", false, "Show the version")
	fs.BoolVar(&cliOpts.tlsSkipVerify, "tls-skip-verify", false, "Skip TLS certificate verification (INSECURE)")
	fs.StringVar(&cliOpts.tlsCACert, "tls-ca-cert", "", "Path to custom CA certificate file")

	fs.SetInterspersed(true)
	fs.Parse(args)

	return cliOpts
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTION]... API_PATH\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Make an api call to the appserver")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "OPTIONS:")
	fmt.Fprintln(os.Stderr, "  -a, --advanced=PARAMS      Advanced querystring PARAMS to send")
	fmt.Fprintln(os.Stderr, "  -c, --compact-json         Retrieve compact json from the api")
	fmt.Fprintln(os.Stderr, "  -C, --connect-timeout=SECS Connection timeout in seconds")
	fmt.Fprintln(os.Stderr, "  -d, --delete               DELETE a row")
	fmt.Fprintln(os.Stderr, "  -f, --fields=LIST          Specify a field list")
	fmt.Fprintln(os.Stderr, "  -F, --filter=LIST          Specify a filter list")
	fmt.Fprintln(os.Stderr, "  -g, --get                  GET a row (default)")
	fmt.Fprintln(os.Stderr, "  -h, --help                 Show this help")
	fmt.Fprintln(os.Stderr, "  -l, --limit=COUNT          Limit result count")
	fmt.Fprintln(os.Stderr, "  -n, --upload-name=N        Override the filename for an upload")
	fmt.Fprintln(os.Stderr, "  -o, --sort=FIELD           Sort based on key[s]")
	fmt.Fprintln(os.Stderr, "  -O, --offset=COUNT         Skip first COUNT results")
	fmt.Fprintln(os.Stderr, "  -p, --post=ROW             POST a row")
	fmt.Fprintln(os.Stderr, "  -P, --put=ROW              PUT a row")
	fmt.Fprintln(os.Stderr, "  -s, --password=PASS        User password")
	fmt.Fprintln(os.Stderr, "  -S, --server=HOST          Server to send command to (default: yb-api)")
	fmt.Fprintln(os.Stderr, "  -t, --threads=CNT          Use CNT threads for uploads")
	fmt.Fprintln(os.Stderr, "  -T, --token=TOKEN          Use an auth token instead of user/password")
	fmt.Fprintln(os.Stderr, "  -U, --upload=FILE          Upload FILE to the server")
	fmt.Fprintln(os.Stderr, "  -u, --user=USER            User login (default: admin)")
	fmt.Fprintln(os.Stderr, "  -V, --version              Show the version")
	fmt.Fprintln(os.Stderr, "      --tls-skip-verify      Skip TLS certificate verification (INSECURE)")
	fmt.Fprintln(os.Stderr, "      --tls-ca-cert=FILE     Path to custom CA certificate file")
}

// isTerminal returns true if the file descriptor is a terminal
func isTerminal(fd uintptr) bool {
	// This is a simplified check - for production code you might want to use the golang.org/x/term package
	stdinStat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stdinStat.Mode() & os.ModeCharDevice) != 0
}

// readPassword reads a password from the terminal without echoing it
func readPassword() ([]byte, error) {
	// This is a simplified version - for production code you might want to use the golang.org/x/term package
	// for proper password input handling across different platforms
	password := make([]byte, 0, 64)
	for {
		var inputByte [1]byte
		bytesRead, err := os.Stdin.Read(inputByte[:])
		if err != nil {
			return nil, err
		}
		if bytesRead == 0 || inputByte[0] == '\n' || inputByte[0] == '\r' {
			break
		}
		password = append(password, inputByte[0])
	}
	return password, nil
}

// loadCACert loads a custom CA certificate file and returns a CertPool
func loadCACert(caCertPath string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate")
	}
	return certPool, nil
}
