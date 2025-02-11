"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Pointer = void 0;
class Pointer {
    constructor(nativePointer) {
        this.nativePointer = nativePointer;
    }
    static async create(address) {
        // TODO: Implement native binding call
        throw new Error('Not implemented');
    }
    async get() {
        // TODO: Implement native binding call
        throw new Error('Not implemented');
    }
    async put(options, payment) {
        // TODO: Implement native binding call
        throw new Error('Not implemented');
    }
    async getCost(key) {
        // TODO: Implement native binding call
        throw new Error('Not implemented');
    }
}
exports.Pointer = Pointer;
