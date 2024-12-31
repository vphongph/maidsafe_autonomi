"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Wallet = void 0;
class Wallet {
    constructor(nativeWallet) {
        this.nativeWallet = nativeWallet;
    }
    static async create(config) {
        // TODO: Implement native binding call
        throw new Error('Not implemented');
    }
    async getAddress() {
        // TODO: Implement native binding call
        throw new Error('Not implemented');
    }
    async getBalance() {
        // TODO: Implement native binding call
        throw new Error('Not implemented');
    }
    async signMessage(message) {
        // TODO: Implement native binding call
        throw new Error('Not implemented');
    }
}
exports.Wallet = Wallet;
