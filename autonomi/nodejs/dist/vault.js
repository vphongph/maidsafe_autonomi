"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Vault = void 0;
class Vault {
    constructor(nativeVault) {
        this.nativeVault = nativeVault;
    }
    static async create(address) {
        // TODO: Implement native binding call
        throw new Error('Not implemented');
    }
    async getCost(key) {
        // TODO: Implement native binding call
        throw new Error('Not implemented');
    }
    async writeBytes(data, payment, options) {
        // TODO: Implement native binding call
        throw new Error('Not implemented');
    }
    async fetchAndDecrypt(key) {
        // TODO: Implement native binding call
        throw new Error('Not implemented');
    }
    async getUserData(key) {
        // TODO: Implement native binding call
        throw new Error('Not implemented');
    }
    async putUserData(key, payment, userData) {
        // TODO: Implement native binding call
        throw new Error('Not implemented');
    }
}
exports.Vault = Vault;
