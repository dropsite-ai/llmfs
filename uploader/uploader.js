// Immediately-invoked function expression to avoid polluting global scope.
(() => {
  // ----- Configuration -----
  let BASE_URL = "http://localhost:8080"  // Default base URL.
  let CHUNK_SIZE = 1024 * 1024;           // Default 1MB chunks.
  let MAX_FILE_CONCURRENCY = 3;           // Maximum number of files uploading concurrently.
  let MAX_CHUNK_RETRIES = 3;              // Maximum retry attempts for a failed chunk.
  let RETRY_DELAY_BASE = 1000;            // Base delay in ms for retry backoff (multiplied by attempt count).

  // ----- Utility Functions -----
  function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ----- Network Helpers -----
  // Initiate an upload for a file.
  async function initiateUpload(file) {
    const response = await fetch(BASE_URL + '/blobs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: file.name,
        total_size: file.size,
        mime_type: file.type || 'application/octet-stream'
      })
    });
    if (!response.ok) {
      throw new Error('Failed to initiate upload: ' + response.statusText);
    }
    return await response.json();
  }

  // Upload a single chunk with retries.
  async function uploadChunk(uploadUrl, offset, chunk) {
    let attempts = 0;
    while (attempts <= MAX_CHUNK_RETRIES) {
      try {
        // uploadUrl already contains the necessary blob_id query param.
        const chunkUrl = `${uploadUrl}&offset=${offset}`;
        const response = await fetch(BASE_URL + chunkUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/octet-stream' },
          body: chunk
        });
        if (!response.ok) {
          throw new Error(`Chunk upload failed: ${response.statusText}`);
        }
        return await response.json();
      } catch (err) {
        attempts++;
        if (attempts > MAX_CHUNK_RETRIES) {
          throw err;
        }
        console.warn(`Chunk at offset ${offset} failed (attempt ${attempts}); retrying in ${RETRY_DELAY_BASE * attempts}ms...`);
        await sleep(RETRY_DELAY_BASE * attempts);
      }
    }
  }

  // Upload a single file (its chunks are sent sequentially).
  async function uploadFile(file) {
    console.log(`Starting upload for ${file.name} (${file.size} bytes)`);
    const initData = await initiateUpload(file);
    const blobId = initData.blob_id;
    const uploadUrl = initData.upload_url;
    console.log(`Upload initiated for ${file.name}: blob_id=${blobId}`);
    
    let offset = 0;
    while (offset < file.size) {
      const chunk = file.slice(offset, offset + CHUNK_SIZE);
      await uploadChunk(uploadUrl, offset, chunk);
      console.log(`Uploaded chunk for ${file.name} at offset ${offset}`);
      offset += chunk.size;
    }
    console.log(`Finished uploading file: ${file.name}`);
  }

  // ----- Concurrency Pool for Files -----
  // A simple pool that limits the number of concurrently running tasks.
  function createFileUploader(concurrencyLimit) {
    const queue = [];
    let activeCount = 0;

    async function runTask(task) {
      activeCount++;
      try {
        await task();
      } finally {
        activeCount--;
        if (queue.length > 0) {
          const nextTask = queue.shift();
          runTask(nextTask);
        }
      }
    }

    // Enqueue a task; if below the limit, start immediately.
    function enqueue(task) {
      return new Promise((resolve, reject) => {
        const wrappedTask = async () => {
          try {
            const result = await task();
            resolve(result);
          } catch (err) {
            reject(err);
          }
        };
        if (activeCount < concurrencyLimit) {
          runTask(wrappedTask);
        } else {
          queue.push(wrappedTask);
        }
      });
    }

    return { enqueue };
  }

  // Process an array of files using the file uploader pool.
  async function processFilesWithConcurrency(files, concurrencyLimit) {
    const uploader = createFileUploader(concurrencyLimit);
    const tasks = files.map(file => uploader.enqueue(() => uploadFile(file)));
    await Promise.all(tasks);
  }

  // ----- File & Directory Traversal -----
  // Recursively walk an entry (File or Directory) and add any File objects to the files array.
  function traverseFileTree(entry, files = []) {
    return new Promise((resolve, reject) => {
      if (entry.isFile) {
        entry.file(file => {
          files.push(file);
          resolve(files);
        }, reject);
      } else if (entry.isDirectory) {
        const dirReader = entry.createReader();
        const readEntries = () => {
          dirReader.readEntries(async (entries) => {
            if (entries.length === 0) {
              resolve(files);
            } else {
              // Process each entry sequentially.
              for (const ent of entries) {
                await traverseFileTree(ent, files);
              }
              readEntries();
            }
          }, reject);
        };
        readEntries();
      } else {
        resolve(files);
      }
    });
  }

  // Extract files from a DataTransfer object (from a drop event).
  async function getDroppedFiles(dataTransfer) {
    const files = [];
    if (dataTransfer.items) {
      const items = Array.from(dataTransfer.items);
      for (const item of items) {
        if (item.kind === 'file') {
          const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
          if (entry) {
            await traverseFileTree(entry, files);
          } else {
            const file = item.getAsFile();
            if (file) files.push(file);
          }
        }
      }
    } else if (dataTransfer.files) {
      files.push(...dataTransfer.files);
    }
    return files;
  }

  // ----- Drag and Drop Handlers -----
  function handleDragOver(e) {
    e.preventDefault();
  }

  function handleDrop(e) {
    e.preventDefault();
    getDroppedFiles(e.dataTransfer)
      .then(files => {
        console.log(`Found ${files.length} file(s) to upload.`);
        processFilesWithConcurrency(files, MAX_FILE_CONCURRENCY)
          .then(() => console.log('All file uploads complete.'))
          .catch(err => console.error('Error during file uploads:', err));
      })
      .catch(err => console.error('Error processing dropped items:', err));
  }

  // Attach event listeners.
  window.addEventListener('dragover', handleDragOver);
  window.addEventListener('drop', handleDrop);

  // ----- Expose a Global API (Optional) -----
  // You can change configuration settings at runtime via this object.
  window.ChunkedUploader = {
    setBaseURL: (url) => { BASE_URL = url; },
    setChunkSize: (size) => { CHUNK_SIZE = size; },
    setFileConcurrency: (limit) => { MAX_FILE_CONCURRENCY = limit; },
    setMaxChunkRetries: (max) => { MAX_CHUNK_RETRIES = max; },
    setRetryDelay: (delay) => { RETRY_DELAY_BASE = delay; }
  };
})();
