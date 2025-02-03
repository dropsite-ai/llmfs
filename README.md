# llmfs

The Open-Source Virtual Filesystem Built for AI and Humans

---

## Overview

LLMFS is a high-performance virtual filesystem server built on SQLite that lets you execute multiple file operations—such as list, read, write, and delete—in a single atomic API call. Designed to cater to both AI systems (LLMs) and human users, LLMFS offers a flexible, secure, and collaborative environment for managing file operations and permissions.

---

## Key Features

- **LLM-Optimized Interface:**  
  A structured JSON API that is both machine-friendly for large language models and intuitive for human operators.

- **Batched Operations:**  
  Execute multiple filesystem commands within one API call, ensuring atomicity and consistency across all operations.

- **User-Centric Data:** Each user owns their own SQLite database, ensuring data isolation and personalized control. Users delegate specific permissions to other LLMFS users, fostering secure collaboration without compromising individual autonomy.

- **Advanced Authentication:**  
  LLMFS uses a robust, multi-layered JWT authentication system that supports:
  - **Bare Metal Root Tokens:** Special high-privilege tokens for administrative (root) access.
  - **User Secrets:** Individual user secrets stored either on the local LLMFS virtual filesystem or managed via an external LLMFS server.

- **Granular Permission Management:**  
  Fine-grained access control enables each user to set and modify permissions on their data, ensuring that only authorized operations are performed.

- **Transactional Integrity:**  
  All filesystem operations are executed in a single transaction, guaranteeing that either all operations succeed or none do—thus preventing partial updates and collisions.

---

## Installation

### Homebrew

Install llmfs via Homebrew:

```bash
brew tap dropsite-ai/homebrew-tap
brew install llmfs
```

### Download Binaries

Alternatively, you can [download binaries directly from our releases](https://github.com/dropsite-ai/llmfs/releases).

### Build from Source

Clone the repository and build using Go:

```bash
git clone https://github.com/dropsite-ai/llmfs.git
cd llmfs
go build -o llmfs cmd/main.go
```

---

## Getting Started

1. **Start the Server**

   Run the executable with default settings:

   ```bash
   ./llmfs -db llmfs.db -owner root -port 8080
   ```

   On first run, llmfs will generate a `llmfs.yaml` configuration file containing critical settings (like your root JWT secret).

2. **Explore the Endpoints**

   - **`/schema`**  
     Returns the JSON Schema that defines the structure for batched filesystem operations.
     
   - **`/auth`**  
     Handles JWT authentication for both root and individual user tokens.
     
   - **`/perform`**  
     Executes your batched filesystem operations. This endpoint is protected and requires valid authentication.

3. **Example Usage**

   Create a JSON payload that adheres to the schema. For example:

   ```json
   [
     {
       "match": {
         "path": {
           "contains": "example.txt"
         },
         "type": "file"
       },
       "operations": {
         "read": true
       }
     }
   ]
   ```

   Send this payload to the `/perform` endpoint using your favorite HTTP client (e.g., `curl` or Postman).

---

## Testing

To run the full test suite, execute:

```bash
make test
```

This command will run both unit and integration tests to ensure everything is functioning as expected.

---

## Releasing

To create a new release, simply run:

```bash
make release
```

This command automates the release process and packages the latest version of llmfs.

---

## Contributing

We welcome contributions from the community! Please refer to our [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on coding standards, testing practices, and the pull request process.

---

## License

LLMFS is released under the [MIT License](LICENSE).