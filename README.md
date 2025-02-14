# LLMFS

**The Open-Source Virtual Filesystem Built for AI and Human Collaboration**

---

## Introduction & Overview

LLMFS is a high-performance virtual filesystem server built on SQLite that lets you execute multiple file operations in a single atomic API call from your large language model (LLM).

---

## Key Features

- **Atomic Operations**  
  Execute multiple file actions (read, write, delete, list) in a single transaction, ensuring *complete success* or *full rollback*. This design prevents partial updates and guards against data corruption, making your workflows ultra-reliable.

- **Granular Permissions**  
  LLMFS provides JSON-based permission control combined with robust JWT authentication. Enjoy fine-tuned read, write, list, and delete permissions on a per-user or even per-directory basis. This ensures secure, customizable access for any collaboration scenario.

- **AI-Optimized API**  
  Specifically designed for large language models and automation scripts, LLMFS’s structured JSON endpoints translate natural language directives into precise filesystem commands—seamlessly integrating with your AI-driven pipelines.

- **Lightweight & Portable**  
  Built on SQLite, LLMFS remains lean and easy to deploy—from full-blown cloud servers to compact edge devices. It delivers enterprise-grade performance without unnecessary overhead, making it perfect for agile, distributed deployments.

- **User Isolation**  
  Each user operates within a dedicated, secure environment. This multi-tenant model keeps data truly isolated while still enabling optional collaboration through explicit permission grants.

---

## Architecture Highlights

- **Robust Transaction Management**  
  Every operation is executed within a single transaction, guaranteeing data integrity even in complex, multi-file workflows.

- **Seamless AI Integration**  
  The system’s API converts natural language instructions into exact filesystem operations, making it a perfect backend for AI-powered applications.

- **Dynamic Security**  
  With JWT-based authentication and a flexible, JSON-driven permission model, LLMFS provides rigorous, adaptable access control across all types of deployments.

---

## Installation

### Homebrew (macOS or Compatible)

If you use Homebrew, install LLMFS with:
```bash
brew tap dropsite-ai/homebrew-tap
brew install llmfs
```

### Download Binaries

Grab the latest pre-built binaries from the [LLMFS GitHub Releases](https://github.com/dropsite-ai/llmfs/releases). Extract them, then run the `llmfs` executable directly.

### Build from Source

1. **Clone the repository**:
   ```bash
   git clone https://github.com/dropsite-ai/llmfs.git
   cd llmfs
   ```
2. **Build using Go**:
   ```bash
   go build -o llmfs cmd/main.go
   ```

---

## Getting Started

LLMFS is engineered for modern AI workflows—empowering your pipelines with atomic, secure file operations that integrate seamlessly into large language models.

### Step 1: Launch an Instance

Choose your preferred deployment:

- **LLMFS Cloud**: Sign up for our managed, zero-ops environment.  
- **Self-Hosted**: Spin up your own LLMFS server for complete control over your infrastructure.

Once you launch LLMFS, it creates a `llmfs.yaml` configuration containing your root JWT secret. You can also create additional non-root user secrets for multi-user setups.

<details>
<summary>Self-Hosted Example</summary>

```bash
./llmfs -db llmfs.db \
        -yaml llmfs.yaml \
        -owner root \
        -port 8080
```

The server listens on the specified port (8080 in this example).
</details>

### Step 2: Integrate Your AI Workflow

LLMFS is built to work hand-in-hand with AI models:

1. **Retrieve System Instructions & Schemas**  
   Send a GET request to `/system`:
   ```bash
   curl http://localhost:8080/system \
        -H "Authorization: Bearer <YOUR_JWT_TOKEN>"
   ```
   The response provides a “system_instruction” plus JSON schemas—guiding the AI on how to format filesystem operation requests.

2. **Embed in Your AI Pipeline**  
   Include these instructions and schemas in your large language model’s prompt or function definitions. This ensures the AI understands the exact request/response structure for LLMFS operations.

### Step 3: Execute Operations

With your instance running and AI integrated, you can now perform atomic file operations:

1. **Construct Your JSON Payload**  
   For example:
   ```json
   [
     {
       "match": {
         "path": { "contains": "example.txt" },
         "type": "file"
       },
       "operations": [
         { "operation": "read" }
       ]
     }
   ]
   ```

2. **Send to `/perform`**  
   ```bash
   curl -X POST http://localhost:8080/perform \
        -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
        -H "Content-Type: application/json" \
        -d @your_request.json
   ```
   All sub-operations are processed in a single transaction, ensuring total success or complete rollback.

3. **Binary Files**  
   Use the `/blobs` endpoint for large file uploads (images, videos, etc.). It supports chunked uploads, partial reads, and more—tailored to handle big files efficiently.

---

## Testing

Run the full test suite with:

```bash
make test
```

This executes both unit and integration tests to ensure LLMFS functions correctly in a variety of scenarios.

---

## Releasing

To package and create a new release:

```bash
make release
```

This automates versioning, tagging, and building binaries for distribution.

---

## Contributing

We warmly welcome community contributions! Refer to [CONTRIBUTING.md](CONTRIBUTING.md) for details on coding standards, testing, and submitting pull requests. Whether you’re fixing a bug, adding a feature, or improving documentation, your input is appreciated.

---

## License

LLMFS is released under the [MIT License](LICENSE).