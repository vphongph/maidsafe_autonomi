/* tslint:disable */
/* eslint-disable */
/* prettier-ignore */

/* auto-generated by NAPI-RS */

const { existsSync, readFileSync } = require('fs')
const { join } = require('path')

const { platform, arch } = process

let nativeBinding = null
let localFileExisted = false
let loadError = null

function isMusl() {
  // For Node 10
  if (!process.report || typeof process.report.getReport !== 'function') {
    try {
      const lddPath = require('child_process').execSync('which ldd').toString().trim()
      return readFileSync(lddPath, 'utf8').includes('musl')
    } catch (e) {
      return true
    }
  } else {
    const { glibcVersionRuntime } = process.report.getReport().header
    return !glibcVersionRuntime
  }
}

switch (platform) {
  case 'android':
    switch (arch) {
      case 'arm64':
        localFileExisted = existsSync(join(__dirname, '@withautonomi/core.android-arm64.node'))
        try {
          if (localFileExisted) {
            nativeBinding = require('./@withautonomi/core.android-arm64.node')
          } else {
            nativeBinding = require('@withautonomi/core-android-arm64')
          }
        } catch (e) {
          loadError = e
        }
        break
      case 'arm':
        localFileExisted = existsSync(join(__dirname, '@withautonomi/core.android-arm-eabi.node'))
        try {
          if (localFileExisted) {
            nativeBinding = require('./@withautonomi/core.android-arm-eabi.node')
          } else {
            nativeBinding = require('@withautonomi/core-android-arm-eabi')
          }
        } catch (e) {
          loadError = e
        }
        break
      default:
        throw new Error(`Unsupported architecture on Android ${arch}`)
    }
    break
  case 'win32':
    switch (arch) {
      case 'x64':
        localFileExisted = existsSync(
          join(__dirname, '@withautonomi/core.win32-x64-msvc.node')
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./@withautonomi/core.win32-x64-msvc.node')
          } else {
            nativeBinding = require('@withautonomi/core-win32-x64-msvc')
          }
        } catch (e) {
          loadError = e
        }
        break
      case 'ia32':
        localFileExisted = existsSync(
          join(__dirname, '@withautonomi/core.win32-ia32-msvc.node')
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./@withautonomi/core.win32-ia32-msvc.node')
          } else {
            nativeBinding = require('@withautonomi/core-win32-ia32-msvc')
          }
        } catch (e) {
          loadError = e
        }
        break
      case 'arm64':
        localFileExisted = existsSync(
          join(__dirname, '@withautonomi/core.win32-arm64-msvc.node')
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./@withautonomi/core.win32-arm64-msvc.node')
          } else {
            nativeBinding = require('@withautonomi/core-win32-arm64-msvc')
          }
        } catch (e) {
          loadError = e
        }
        break
      default:
        throw new Error(`Unsupported architecture on Windows: ${arch}`)
    }
    break
  case 'darwin':
    localFileExisted = existsSync(join(__dirname, '@withautonomi/core.darwin-universal.node'))
    try {
      if (localFileExisted) {
        nativeBinding = require('./@withautonomi/core.darwin-universal.node')
      } else {
        nativeBinding = require('@withautonomi/core-darwin-universal')
      }
      break
    } catch {}
    switch (arch) {
      case 'x64':
        localFileExisted = existsSync(join(__dirname, '@withautonomi/core.darwin-x64.node'))
        try {
          if (localFileExisted) {
            nativeBinding = require('./@withautonomi/core.darwin-x64.node')
          } else {
            nativeBinding = require('@withautonomi/core-darwin-x64')
          }
        } catch (e) {
          loadError = e
        }
        break
      case 'arm64':
        localFileExisted = existsSync(
          join(__dirname, '@withautonomi/core.darwin-arm64.node')
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./@withautonomi/core.darwin-arm64.node')
          } else {
            nativeBinding = require('@withautonomi/core-darwin-arm64')
          }
        } catch (e) {
          loadError = e
        }
        break
      default:
        throw new Error(`Unsupported architecture on macOS: ${arch}`)
    }
    break
  case 'freebsd':
    if (arch !== 'x64') {
      throw new Error(`Unsupported architecture on FreeBSD: ${arch}`)
    }
    localFileExisted = existsSync(join(__dirname, '@withautonomi/core.freebsd-x64.node'))
    try {
      if (localFileExisted) {
        nativeBinding = require('./@withautonomi/core.freebsd-x64.node')
      } else {
        nativeBinding = require('@withautonomi/core-freebsd-x64')
      }
    } catch (e) {
      loadError = e
    }
    break
  case 'linux':
    switch (arch) {
      case 'x64':
        if (isMusl()) {
          localFileExisted = existsSync(
            join(__dirname, '@withautonomi/core.linux-x64-musl.node')
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./@withautonomi/core.linux-x64-musl.node')
            } else {
              nativeBinding = require('@withautonomi/core-linux-x64-musl')
            }
          } catch (e) {
            loadError = e
          }
        } else {
          localFileExisted = existsSync(
            join(__dirname, '@withautonomi/core.linux-x64-gnu.node')
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./@withautonomi/core.linux-x64-gnu.node')
            } else {
              nativeBinding = require('@withautonomi/core-linux-x64-gnu')
            }
          } catch (e) {
            loadError = e
          }
        }
        break
      case 'arm64':
        if (isMusl()) {
          localFileExisted = existsSync(
            join(__dirname, '@withautonomi/core.linux-arm64-musl.node')
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./@withautonomi/core.linux-arm64-musl.node')
            } else {
              nativeBinding = require('@withautonomi/core-linux-arm64-musl')
            }
          } catch (e) {
            loadError = e
          }
        } else {
          localFileExisted = existsSync(
            join(__dirname, '@withautonomi/core.linux-arm64-gnu.node')
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./@withautonomi/core.linux-arm64-gnu.node')
            } else {
              nativeBinding = require('@withautonomi/core-linux-arm64-gnu')
            }
          } catch (e) {
            loadError = e
          }
        }
        break
      case 'arm':
        if (isMusl()) {
          localFileExisted = existsSync(
            join(__dirname, '@withautonomi/core.linux-arm-musleabihf.node')
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./@withautonomi/core.linux-arm-musleabihf.node')
            } else {
              nativeBinding = require('@withautonomi/core-linux-arm-musleabihf')
            }
          } catch (e) {
            loadError = e
          }
        } else {
          localFileExisted = existsSync(
            join(__dirname, '@withautonomi/core.linux-arm-gnueabihf.node')
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./@withautonomi/core.linux-arm-gnueabihf.node')
            } else {
              nativeBinding = require('@withautonomi/core-linux-arm-gnueabihf')
            }
          } catch (e) {
            loadError = e
          }
        }
        break
      case 'riscv64':
        if (isMusl()) {
          localFileExisted = existsSync(
            join(__dirname, '@withautonomi/core.linux-riscv64-musl.node')
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./@withautonomi/core.linux-riscv64-musl.node')
            } else {
              nativeBinding = require('@withautonomi/core-linux-riscv64-musl')
            }
          } catch (e) {
            loadError = e
          }
        } else {
          localFileExisted = existsSync(
            join(__dirname, '@withautonomi/core.linux-riscv64-gnu.node')
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./@withautonomi/core.linux-riscv64-gnu.node')
            } else {
              nativeBinding = require('@withautonomi/core-linux-riscv64-gnu')
            }
          } catch (e) {
            loadError = e
          }
        }
        break
      case 's390x':
        localFileExisted = existsSync(
          join(__dirname, '@withautonomi/core.linux-s390x-gnu.node')
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./@withautonomi/core.linux-s390x-gnu.node')
          } else {
            nativeBinding = require('@withautonomi/core-linux-s390x-gnu')
          }
        } catch (e) {
          loadError = e
        }
        break
      default:
        throw new Error(`Unsupported architecture on Linux: ${arch}`)
    }
    break
  default:
    throw new Error(`Unsupported OS: ${platform}, architecture: ${arch}`)
}

if (!nativeBinding) {
  if (loadError) {
    throw loadError
  }
  throw new Error(`Failed to load native binding`)
}

const { Client, ChunkPut, GraphEntryPut, ScratchpadPut, PointerPut, DataPutResult, DataPutPublicResult, ArchivePutResult, ArchivePutPublicResult, DirContentUpload, DirUpload, FileContentUpload, DirContentUploadPublic, DirUploadPublic, FileContentUploadPublic, FetchAndDecryptVault, RegisterCreate, GraphEntryDescendant, XorName, ChunkAddress, GraphEntryAddress, DataAddress, ArchiveAddress, Wallet, PaymentOption, Network, PublicKey, SecretKey, GraphEntry, Pointer, PointerTarget, PointerAddress, Scratchpad, ScratchpadAddress, DataMapChunk, PrivateArchiveDataMap, PrivateArchive, VaultSecretKey, UserData, VaultContentType, RegisterAddress, RegisterHistory, PublicArchive } = nativeBinding

module.exports.Client = Client
module.exports.ChunkPut = ChunkPut
module.exports.GraphEntryPut = GraphEntryPut
module.exports.ScratchpadPut = ScratchpadPut
module.exports.PointerPut = PointerPut
module.exports.DataPutResult = DataPutResult
module.exports.DataPutPublicResult = DataPutPublicResult
module.exports.ArchivePutResult = ArchivePutResult
module.exports.ArchivePutPublicResult = ArchivePutPublicResult
module.exports.DirContentUpload = DirContentUpload
module.exports.DirUpload = DirUpload
module.exports.FileContentUpload = FileContentUpload
module.exports.DirContentUploadPublic = DirContentUploadPublic
module.exports.DirUploadPublic = DirUploadPublic
module.exports.FileContentUploadPublic = FileContentUploadPublic
module.exports.FetchAndDecryptVault = FetchAndDecryptVault
module.exports.RegisterCreate = RegisterCreate
module.exports.GraphEntryDescendant = GraphEntryDescendant
module.exports.XorName = XorName
module.exports.ChunkAddress = ChunkAddress
module.exports.GraphEntryAddress = GraphEntryAddress
module.exports.DataAddress = DataAddress
module.exports.ArchiveAddress = ArchiveAddress
module.exports.Wallet = Wallet
module.exports.PaymentOption = PaymentOption
module.exports.Network = Network
module.exports.PublicKey = PublicKey
module.exports.SecretKey = SecretKey
module.exports.GraphEntry = GraphEntry
module.exports.Pointer = Pointer
module.exports.PointerTarget = PointerTarget
module.exports.PointerAddress = PointerAddress
module.exports.Scratchpad = Scratchpad
module.exports.ScratchpadAddress = ScratchpadAddress
module.exports.DataMapChunk = DataMapChunk
module.exports.PrivateArchiveDataMap = PrivateArchiveDataMap
module.exports.PrivateArchive = PrivateArchive
module.exports.VaultSecretKey = VaultSecretKey
module.exports.UserData = UserData
module.exports.VaultContentType = VaultContentType
module.exports.RegisterAddress = RegisterAddress
module.exports.RegisterHistory = RegisterHistory
module.exports.PublicArchive = PublicArchive
