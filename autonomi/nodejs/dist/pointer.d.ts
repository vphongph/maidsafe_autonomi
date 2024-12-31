import { PointerOptions, PaymentOption } from './types';
export declare class Pointer {
    private nativePointer;
    private constructor();
    static create(address: string): Promise<Pointer>;
    get(): Promise<any>;
    put(options: PointerOptions, payment: PaymentOption): Promise<void>;
    getCost(key: string): Promise<string>;
}
