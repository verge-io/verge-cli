# Verge CLI (`verge-cli`)

`verge-cli` is a modern, cross-platform command-line interface (CLI) tool designed for seamless interaction with the VergeOS API.

## Features

-   **Cross-platform Support**: Fully compatible with Windows, macOS, and Linux.
-   **Comprehensive API Interaction**: Supports GET, POST, PUT, DELETE HTTP methods.
-   **Flexible Authentication**: Username/password and token-based authentication mechanisms.
-   **Efficient File Handling**: Features fast, parallel file uploading with progress indicators.
-   **Powerful Data Queries**: Extensive support for query parameters including field selection, filtering, sorting, and pagination (limit/offset).
-   **Advanced Customization**: Allows specification of custom headers and advanced query string parameters.
-   **TLS Configuration**: Supports skipping TLS verification (for testing) and using custom CA certificates.

## Installation & Configuration

### Pre-built Binaries

The easiest way to install `verge-cli` is by downloading the latest pre-built binary for your operating system from the [GitHub Releases page](https://github.com/verge-io/verge-cli/releases).

After downloading, ensure the binary is executable (on Linux/macOS):
```bash
chmod +x verge-cli
```
It's recommended to place the binary in a directory included in your system's PATH (e.g., `/usr/local/bin` or `~/bin`).

### Building from Source

If you prefer to build from source, you'll need Go (version 1.13 or newer) installed:
```bash
git clone https://github.com/verge-io/verge-cli.git
cd verge-cli
go build -o verge-cli
```

#### Cross-compilation
To build `verge-cli` for different platforms:
```bash
# For Windows (64-bit)
GOOS=windows GOARCH=amd64 go build -o verge-cli.exe

# For macOS (64-bit Intel)
GOOS=darwin GOARCH=amd64 go build -o verge-cli-mac

# For Linux (64-bit)
GOOS=linux GOARCH=amd64 go build -o verge-cli-linux
```

### Configuration

`verge-cli` can be configured using environment variables for convenience and security:

-   `VERGE_USER`: Sets the default username. Overrides the built-in default (`admin`).
    ```bash
    export VERGE_USER="your_username"
    ```
-   `VERGE_PASSWORD`: Sets the user password. Note: Storing passwords in environment variables can be a security risk. Prefer interactive password input or token authentication.
    ```bash
    export VERGE_PASSWORD="your_password"
    ```
-   `VERGE_TOKEN`: Sets the authentication token. This is the recommended method for scripted or automated environments.
    ```bash
    export VERGE_TOKEN="your_api_token"
    ```
-   `VERGE_SERVER`: Sets the default server hostname or IP address (e.g., `my.vergeos.system`). Overrides the built-in default (`vergeos`).
    ```bash
    export VERGE_SERVER="your_vergeos_host"
    ```

## Basic Usage

The general syntax for `verge-cli` is:
```bash
verge-cli [OPTIONS]... API_PATH
```
-   `API_PATH`: The specific VergeOS API endpoint you want to interact with (e.g., `/v4/vms`, `/v4/storage/pools`).
-   `OPTIONS`: Flags that modify the command's behavior, such as specifying the HTTP method, authentication details, or data payload.

**Example: Listing Virtual Machines**
```bash
verge-cli --server=your.vergeos.ip --user=admin /v4/vms
# You will be prompted for the password
```

**Example: Using a Token**
```bash
verge-cli --server=your.vergeos.ip --token=$VERGE_TOKEN /v4/vms
```

## Command Reference

Here is a list of all available command-line options:

```
OPTIONS:
  -a, --advanced=PARAMS      Advanced querystring PARAMS to send (e.g., "param1=value1&param2=value2")
  -c, --compact-json         Retrieve compact JSON (no indentation) from the API
  -C, --connect-timeout=SECS Connection timeout in seconds (default: system-dependent)
  -d, --delete               Perform a DELETE request on the API_PATH
  -f, --fields=LIST          Comma-separated list of fields to retrieve (e.g., "name,\$key,ram")
  -F, --filter=LIST          Comma-separated list of filters to apply (e.g., "name eq 'MyVM',ram gt 2048")
  -g, --get                  Perform a GET request (default action if no other method is specified)
  -h, --help                 Show this help message and exit
  -H, --header=LIST          Comma-separated list of custom headers (e.g., "X-Custom-Header:value")
  -l, --limit=COUNT          Limit the number of results returned
  -n, --upload-name=N        Override the filename for an upload operation
  -o, --sort=FIELD           Sort results based on specified field(s) (e.g., "name" or "-ram" for descending)
  -O, --offset=COUNT         Skip the first COUNT results (for pagination)
  -p, --post=ROW             Perform a POST request with the given JSON data ROW
  -P, --put=ROW              Perform a PUT request with the given JSON data ROW
  -s, --password=PASS        User password (if not provided, will prompt securely)
  -S, --server=HOST          Server hostname or IP to send the command to (default: "vergeos")
  -t, --threads=CNT          Number of concurrent threads for uploads (default: 8)
  -T, --token=TOKEN          Authentication token to use instead of username/password
  -U, --upload=FILE          Upload the specified FILE to the server
  -u, --user=USER            User login name (default: "admin")
  -V, --version              Show the version information and exit
      --tls-skip-verify      Skip TLS certificate verification (INSECURE: use only for testing or trusted environments)
      --tls-ca-cert=PATH     Path to a custom CA certificate file for TLS verification
```

## Examples

### 1. Retrieve a List of VMs with Specific Fields and Filters
```bash
verge-cli --server=10.0.0.100 --user=admin \
  --fields='name,$key,ram,machine#status#status as machine_status' \
  --filter='is_snapshot eq false,ram gt 2048' \
  /v4/vms
```

### 2. Create a New Virtual Machine from a JSON File
Create a file `new_vm.json`:
```json
{
  "name": "MyNewWebServer",
  "enabled": true,
  "description": "Primary web server",
  "os_family": "linux",
  "cpu_cores": 4,
  "ram": "8192"
}
```
Then run:
```bash
verge-cli --server=10.0.0.100 --user=admin --post=@new_vm.json /v4/vms
```

### 3. Update an Existing Virtual Machine's Description
```bash
verge-cli --server=10.0.0.100 --user=admin \
  --put='{"description":"Updated description for web server"}' \
  /v4/vms/your-vm-id
```

### 4. Upload an ISO Image with Custom Threads and Name
```bash
verge-cli --server=10.0.0.100 --user=admin \
  --upload=/path/to/ubuntu-server.iso \
  --upload-name=ubuntu-latest.iso \
  --threads=16 \
  /v4/files
```


## API Discovery

To effectively use `verge-cli`, you need to know the available VergeOS API endpoints and their parameters.

-   **Official VergeOS API Documentation**: The primary and most comprehensive source for API information is the official documentation available at [https://docs.verge.io](https://docs.verge.io). This documentation details all available API paths, request/response formats, and supported parameters.
-   **Swagger/OpenAPI Interface (Verge UI)**: VergeOS provides an interactive Swagger (OpenAPI) interface for API exploration. You can access it directly within the Verge UI:
    -   Navigate to **System → API Documentation**.
    -   Alternatively, append `/#swagger` to your VergeOS system's URL (e.g., `https://your.vergeos.system/#swagger`).
-   **Browser Developer Tools**: When using the VergeOS web interface, you can use your browser's developer tools (usually the "Network" tab) to observe the API calls being made. This can help you understand how to structure your `verge-cli` commands for specific actions.

## Security

-   **HTTPS**: All connections are made over HTTPS by default, ensuring data is encrypted in transit.
-   **TLS Verification**:
    -   TLS certificate verification is enabled by default.
    -   `--tls-skip-verify`: Disables certificate validation. **This is insecure and should only be used for testing or in fully trusted environments.**
    -   `--tls-ca-cert <path>`: Allows you to specify a custom CA certificate file for connecting to servers with self-signed or private CA certificates securely.
-   **Authentication**:
    -   **Passwords**: If `--password` is not provided, `verge-cli` will prompt for it securely (input is not echoed).
    -   **Tokens**: Using an authentication token (`--token` or `VERGE_TOKEN` environment variable) is generally more secure for scripts and automation than embedding passwords.
-   **Environment Variables**: While `VERGE_PASSWORD` is supported, be cautious as command history or process listings might expose it. `VERGE_TOKEN` is a safer alternative for non-interactive use.

## Exit Codes

`verge-cli` uses standardized exit codes to indicate the outcome of operations, facilitating scripting and automation:

| Exit Code | Meaning                  |
| :-------- | :----------------------- |
| 0         | Success                  |
| 1         | General error            |
| 2         | Invalid input/arguments  |
| 3         | Authentication failure   |
| 4         | API error (server-side)  |
| 5         | Configuration error      |
| 6         | Resource not found (404) |
| 130       | User interruption (Ctrl+C) |
| 255       | Unexpected internal error|

## Troubleshooting

### Common Issues

-   **Connection Refused/Timeout**:
    -   Verify the server address or hostname (`--server` or `VERGE_SERVER`).
    -   Check network connectivity to the VergeOS system (ping, firewall rules).
    -   Ensure the VergeOS API service is running.
-   **Authentication Failure (Exit Code 3)**:
    -   Double-check username and password.
    -   Ensure your API token is valid and has not expired.
    -   Verify user permissions for the requested API endpoint.
-   **API Error (Exit Code 4)**:
    -   The API server responded with an error (e.g., 4xx or 5xx HTTP status). The output from `verge-cli` should include the API's error message.
    -   Check the API documentation for the specific endpoint and parameters.
    -   Ensure your JSON payloads for POST/PUT requests are correctly formatted.
-   **Invalid Input (Exit Code 2)**:
    -   Check your command syntax and flags. Use `verge-cli --help`.
-   **Resource Not Found (Exit Code 6 / HTTP 404)**:
    -   The specified `API_PATH` or resource ID (e.g., VM UUID) does not exist.

### HTTP Status Codes

`verge-cli` typically passes through HTTP status codes from the API. Common categories:
-   `2xx` (e.g., `200 OK`, `201 Created`, `204 No Content`): Success.
-   `4xx` (e.g., `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found`): Client-side error. Check your request, authentication, and permissions.
-   `5xx` (e.g., `500 Internal Server Error`, `503 Service Unavailable`): Server-side error. Contact your VergeOS administrator.

For more detailed debugging, you can often increase verbosity if the API supports it via an advanced parameter, or inspect API logs on the VergeOS system.
