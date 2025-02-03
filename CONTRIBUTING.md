# Contributing to LLMFS

Thank you for your interest in contributing to **LLMFS**! Whether you're fixing a bug, adding a feature, or improving documentation, we appreciate your efforts in making this project better.

---

## Getting Started

### 1. Fork & Clone the Repository

First, fork the repository to your GitHub account and then clone it locally:

```bash
git clone https://github.com/your-username/llmfs.git
cd llmfs
```

### 2. Install Dependencies

Ensure you have Go installed (minimum **Go 1.18**). Then, install dependencies:

```bash
go mod tidy
```

### 3. Build the Project

Compile the project to ensure everything works:

```bash
go build -o llmfs cmd/main.go
```

### 4. Run Tests

Before making changes, verify that the existing tests pass:

```bash
make test
```

---

## Contribution Guidelines

### Reporting Issues

If you find a bug, security vulnerability, or have a feature request, please open a [GitHub Issue](https://github.com/dropsite-ai/llmfs/issues). Be sure to include:

- A clear and concise title.
- Steps to reproduce (if applicable).
- Expected vs. actual behavior.
- Any relevant logs or screenshots.

### Submitting Code Changes

1. **Create a Branch**  
   Use a descriptive name for your branch:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**  
   Follow the coding style and best practices outlined in this document.

3. **Write Tests**  
   If you’re adding new functionality, write unit tests to cover your changes.

4. **Commit Your Changes**  
   Keep your commit messages concise and meaningful:

   ```bash
   git commit -m "Add feature: description of feature"
   ```

5. **Push to Your Fork**  
   Push your branch to your forked repository:

   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request (PR)**  
   - Open a PR against the `main` branch.
   - Provide a clear title and description of your changes.
   - Reference related issues if applicable.
   - Follow the PR template (if available).

---

## Code Style & Best Practices

- Follow Go best practices and idioms.
- Format code before committing:

  ```bash
  go fmt ./...
  ```

- Keep functions small and focused.
- Write meaningful comments where necessary.

---

## Testing

LLMFS includes both unit and integration tests. Before submitting a PR, ensure that all tests pass:

```bash
make test
```

For integration tests, ensure you have a running LLMFS instance:

```bash
./llmfs -db llmfs_test.db -owner root -port 8080
```

Then, run:

```bash
go test -v ./...
```

---

## Releasing

If you're a maintainer and need to release a new version:

1. Update the version in `VERSION` and `CHANGELOG.md`.
2. Run:

   ```bash
   make release
   ```

---

## Community & Support

- Join discussions in [GitHub Discussions](https://github.com/dropsite-ai/llmfs/discussions).
- Reach out via Issues or PR comments.

---

## License

By contributing to LLMFS, you agree that your code will be licensed under the [MIT License](LICENSE).

Happy coding! 🚀