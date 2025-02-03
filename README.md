# llmfs

The Open-Source Filesystem Built for AI and Humans.

## Install

Download from [Releases](https://github.com/dropsite-ai/llmfs/releases):

```bash
tar -xzf llmfs_Darwin_arm64.tar.gz
chmod +x llmfs
sudo mv llmfs /usr/local/bin/
```

Or manually build and install:

```bash
git clone git@github.com:dropsite-ai/llmfs.git
cd llmfs
make install
```

## Test

```bash
make test
```

## Release

```bash
make release
```