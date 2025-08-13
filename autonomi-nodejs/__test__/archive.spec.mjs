import test from 'ava'
import path from 'path'
import fs from 'fs'
import os from 'os'
import crypto from 'crypto'
import { 
  Client, 
  Wallet, 
  Network, 
  PaymentOption, 
  PrivateArchive,
  PublicArchive,
  SecretKey,
  DataAddress,
  XorName,
  Metadata
} from '../index.js'

// Utility function to compute SHA256 hash of a file
function computeSha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    
    stream.on('error', err => reject(err));
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

// Utility function to compute SHA256 hash of a directory
async function computeDirSha256(dir) {
  const hash = crypto.createHash('sha256');
  
  // Get all files recursively
  async function getFiles(dir) {
    const entries = await fs.promises.readdir(dir, { withFileTypes: true });
    const files = await Promise.all(entries.map(entry => {
      const res = path.resolve(dir, entry.name);
      return entry.isDirectory() ? getFiles(res) : res;
    }));
    return files.flat();
  }
  
  // Hash all files in the directory
  const files = await getFiles(dir);
  
  // Sort files by path to ensure consistent ordering across different file systems
  files.sort();
  
  for (const file of files) {
    const fileHash = await computeSha256(file);

    hash.update(fileHash);
  }
  
  return hash.digest('hex');
}

// Utility function to get detailed directory listing (similar to ls -l with recursive tree)
async function getDirectoryListing(dirPath, indent = '') {
  try {
    const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });
    const listing = await Promise.all(entries.map(async (entry) => {
      const fullPath = path.join(dirPath, entry.name);
      const stats = await fs.promises.stat(fullPath);
      
      if (entry.isDirectory()) {
        const dirLine = `${indent}drwxr-xr-x ${stats.uid || 0} ${stats.gid || 0} ${stats.size} ${stats.mtime.toISOString()} ${entry.name}/`;
        
        // Recursively get contents of subdirectory
        const subListing = await getDirectoryListing(fullPath, indent + '  ');
        return [dirLine, subListing].filter(Boolean).join('\n');
      } else {
        const permissions = (stats.mode & 0o777).toString(8).padStart(3, '0');
        return `${indent}-rw-r--r-- ${stats.uid || 0} ${stats.gid || 0} ${stats.size} ${stats.mtime.toISOString()} ${entry.name}`;
      }
    }));
    
    return listing.join('\n');
  } catch (error) {
    return `${indent}Error reading directory: ${error.message}`;
  }
}

// Utility function to get content of mismatched files for debugging
async function getMismatchedFileContents(sourceDir, destDir, maxSize = 1024) {
  try {
    const sourceFiles = await getAllFiles(sourceDir);
    const destFiles = await getAllFiles(destDir);
    
    const mismatchedFiles = [];
    
    // Compare files that exist in both directories
    for (const sourceFile of sourceFiles) {
      const relativePath = path.relative(sourceDir, sourceFile);
      const destFile = path.join(destDir, relativePath);
      
      if (fs.existsSync(destFile)) {
        const sourceHash = await computeSha256(sourceFile);
        const destHash = await computeSha256(destFile);
        
        if (sourceHash !== destHash) {
          mismatchedFiles.push({
            relativePath,
            sourceHash,
            destHash,
            sourceFile,
            destFile
          });
        }
      }
    }
    
    if (mismatchedFiles.length === 0) {
      return 'No mismatched files found (all existing files have matching hashes)';
    }
    
    let result = `Found ${mismatchedFiles.length} file(s) with mismatched hashes:\n`;
    
    for (const file of mismatchedFiles) {
      const sourceStats = await fs.promises.stat(file.sourceFile);
      const destStats = await fs.promises.stat(file.destFile);
      
      result += `\nFile: ${file.relativePath}\n`;
      result += `Source hash: ${file.sourceHash}\n`;
      result += `Dest hash: ${file.destHash}\n`;
      result += `Source size: ${sourceStats.size} bytes\n`;
      result += `Dest size: ${destStats.size} bytes\n`;
      
      // Show content of both source and destination files for comparison
      const sourceSize = sourceStats.size;
      const destSize = destStats.size;
      
      if (sourceSize <= maxSize && destSize <= maxSize) {
        try {
          const sourceContent = await fs.promises.readFile(file.sourceFile, 'utf8');
          const destContent = await fs.promises.readFile(file.destFile, 'utf8');
          
          const escapedSourceContent = sourceContent
            .replace(/\\/g, '\\\\')
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '\\r')
            .replace(/\t/g, '\\t');
          
          const escapedDestContent = destContent
            .replace(/\\/g, '\\\\')
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '\\r')
            .replace(/\t/g, '\\t');
          
          result += `Source content:\n${escapedSourceContent}\n`;
          result += `Destination content:\n${escapedDestContent}\n`;
        } catch (error) {
          result += `Error reading content: ${error.message}\n`;
        }
      } else if (sourceSize <= maxSize) {
        try {
          const sourceContent = await fs.promises.readFile(file.sourceFile, 'utf8');
          const escapedSourceContent = sourceContent
            .replace(/\\/g, '\\\\')
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '\\r')
            .replace(/\t/g, '\\t');
          
          result += `Source content:\n${escapedSourceContent}\n`;
          result += `Destination content: File too large (${destSize} bytes) to show\n`;
        } catch (error) {
          result += `Error reading source content: ${error.message}\n`;
        }
      } else if (destSize <= maxSize) {
        try {
          const destContent = await fs.promises.readFile(file.destFile, 'utf8');
          const escapedDestContent = destContent
            .replace(/\\/g, '\\\\')
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '\\r')
            .replace(/\t/g, '\\t');
          
          result += `Source content: File too large (${sourceSize} bytes) to show\n`;
          result += `Destination content:\n${escapedDestContent}\n`;
        } catch (error) {
          result += `Error reading destination content: ${error.message}\n`;
        }
      } else {
        result += `Source content: File too large (${sourceSize} bytes) to show\n`;
        result += `Destination content: File too large (${destSize} bytes) to show\n`;
      }
    }
    
    return result;
    
  } catch (error) {
    return `Error analyzing mismatched files: ${error.message}`;
  }
}

// Helper function to get all files recursively
async function getAllFiles(dirPath) {
  const files = [];
  
  async function collectFiles(currentPath) {
    const entries = await fs.promises.readdir(currentPath, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);
      
      if (entry.isDirectory()) {
        await collectFiles(fullPath);
      } else {
        files.push(fullPath);
      }
    }
  }
  
  await collectFiles(dirPath);
  return files.sort(); // Sort for consistent ordering
}

test('private archive - upload and download directory', async (t) => {
  // Initialize client
  const client = await Client.initLocal();
  const wallet = Wallet.newFromPrivateKey(new Network(true), "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
  const paymentOption = PaymentOption.fromWallet(wallet);
  
  // Define source and destination directories
  const sourceDir = path.join('../autonomi', 'tests', 'file', 'test_dir');
  const destDir = path.join(os.tmpdir());
  
  // Upload directory content
  const { cost, archive } = await client.dirContentUpload(sourceDir, paymentOption);
  
  // Verify cost is returned as a string
  t.true(typeof cost === 'string');
  
  // Upload the archive
  const { cost: archiveCost, dataMap } = await client.archivePut(archive, paymentOption);
  
  // Verify archive cost is returned as a string
  t.true(typeof archiveCost === 'string');
  
  // Download the archive
  await client.dirDownload(dataMap, destDir);
  
  // Compare the hash of source and destination directories
  const sourceHash = await computeDirSha256(sourceDir);
  const destHash = await computeDirSha256(path.join(destDir, 'test_dir'));
  
  if (sourceHash !== destHash) {
    // Get detailed directory listings for debugging
    const sourceListing = await getDirectoryListing(sourceDir);
    const destListing = await getDirectoryListing(path.join(destDir, 'test_dir'));
    
    // Get content of mismatched files for debugging
    const mismatchedContent = await getMismatchedFileContents(sourceDir, path.join(destDir, 'test_dir'));
    
    const errorMsg = `Source and destination directory hashes should match.
Source hash: ${sourceHash}
Destination hash: ${destHash}

Source directory (${sourceDir}):
${sourceListing}

Destination directory (${path.join(destDir, 'test_dir')}):
${destListing}

${mismatchedContent}`;
    
    t.fail(errorMsg);
  } else {
    t.pass('Source and destination directory hashes match');
  }
});

test('public archive - upload and download directory', async (t) => {
  // Initialize client
  const client = await Client.initLocal();
  const wallet = Wallet.newFromPrivateKey(new Network(true), "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
  const paymentOption = PaymentOption.fromWallet(wallet);
  
  // Define source and destination directories
  const sourceDir = path.join('../autonomi', 'tests', 'file', 'test_dir');
  const destDir = os.tmpdir();
  
  // Upload directory content as public
  const { cost, addr: archive } = await client.dirContentUploadPublic(sourceDir, paymentOption);
  
  // Verify cost is returned as a string
  t.true(typeof cost === 'string');
  
  // Upload the archive
  const { cost: archiveCost, addr } = await client.archivePutPublic(archive, paymentOption);
  
  // Verify archive cost is returned as a string
  t.true(typeof archiveCost === 'string');
  
  // Download the archive
  await client.dirDownloadPublic(addr, destDir);
  
  // Compare the hash of source and destination directories
  const sourceHash = await computeDirSha256(sourceDir);
  const destHash = await computeDirSha256(path.join(destDir, 'test_dir'));
  
  if (sourceHash !== destHash) {
    // Get detailed directory listings for debugging
    const sourceListing = await getDirectoryListing(sourceDir);
    const destListing = await getDirectoryListing(path.join(destDir, 'test_dir'));
    
    // Get content of mismatched files for debugging
    const mismatchedContent = await getMismatchedFileContents(sourceDir, path.join(destDir, 'test_dir'));
    
    const errorMsg = `Source and destination directory hashes should match.
Source hash: ${sourceHash}
Destination hash: ${destHash}

Source directory (${sourceDir}):
${sourceListing}

Destination directory (${path.join(destDir, 'test_dir')}):
${destListing}

${mismatchedContent}`;
    
    t.fail(errorMsg);
  } else {
    t.pass('Source and destination directory hashes match');
  }
});

test('archive advanced use', async (t) => {
  // Initialize client
  const client = await Client.initLocal();
  const wallet = Wallet.newFromPrivateKey(new Network(true), "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
  const paymentOption = PaymentOption.fromWallet(wallet);
  
  // Define source and destination directories
  const sourceDirA = path.join('../autonomi', 'tests', 'file', 'test_dir', 'dir_a');
  const fileB = path.join('../autonomi', 'tests', 'file', 'test_dir', 'example_file_b');
  const fileA = path.join('../autonomi', 'tests', 'file', 'test_dir', 'example_file_a');
  const destDir = os.tmpdir();
  
  // Upload directory content
  const { cost, archive } = await client.dirContentUpload(sourceDirA, paymentOption);
  
  // Verify cost is returned as a string
  t.true(typeof cost === 'string');
  
  // Upload an additional file separately
  const { cost: fileBCost, dataMap: fileBDataMap } = await client.fileContentUpload(fileB, paymentOption);
  
  // Verify file cost is returned as a string
  t.true(typeof fileBCost === 'string');
  
  // Add the file to the archive with custom metadata
  const now = Math.floor(Date.now() / 1000);
  // Create metadata with all custom fields at once
  const fileBMetadata = Metadata.withCustomFields(
    BigInt(now),
    BigInt(now),
    BigInt(13),
    "Extra metadata for fileB"
  );
  archive.addFile("example_file_b", fileBDataMap, fileBMetadata);
  
  // Upload another additional file separately
  const { cost: fileACost, dataMap: fileADataMap } = await client.fileContentUpload(fileA, paymentOption);
  
  // Verify file cost is returned as a string
  t.true(typeof fileACost === 'string');
  
  // Also add this file to archive
  const fileAMetadata = Metadata.newWithSize(BigInt(13)); // size 13 bytes
  archive.addFile("example_file_a", fileADataMap, fileAMetadata);
  
  // Check that we have the expected files in the archive
  const files = archive.files();
  t.is(files.length, 4); // Two files from dir_a plus the two we added
  
  // Upload the archive
  const { cost: archiveCost, dataMap } = await client.archivePut(archive, paymentOption);
  
  // Verify archive cost is returned as a string
  t.true(typeof archiveCost === 'string');
});

// Test storing an archive in vault
test('file into vault', async (t) => {
  // Initialize client
  const client = await Client.initLocal();
  const wallet = Wallet.newFromPrivateKey(new Network(true), "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
  const paymentOption = PaymentOption.fromWallet(wallet);
  
  // Create a random secret key
  const secretKey = SecretKey.random();
  
  // Define source directory
  const sourceDir = path.join('../autonomi', 'tests', 'file', 'test_dir');
  
  // Upload directory content as public
  const { cost: dirCost, addr } = await client.dirUploadPublic(sourceDir, paymentOption);
  
  // Verify cost is returned as a string
  t.true(typeof dirCost === 'string');
  
  // Get the archive
  const archive = await client.archiveGetPublic(addr);
  
  // Convert archive to bytes and write to vault
  const archiveBytes = archive.toBytes();
  t.true(archiveBytes.length > 0, 'Archive bytes should not be empty');
  
  // Test converting bytes back to archive
  const recoveredArchive = PublicArchive.fromBytes(archiveBytes);
  const recoveredFiles = recoveredArchive.addresses();
  t.true(recoveredFiles.length > 0, 'Recovered archive should contain files');
});
