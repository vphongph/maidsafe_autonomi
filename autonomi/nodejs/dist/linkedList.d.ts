import { GarphEntryOptions, PaymentOption } from './types';
export declare class GarphEntry {
    private nativeList;
    private constructor();
    static create(address: string): Promise<GarphEntry>;
    get(): Promise<any[]>;
    put(options: GarphEntryOptions, payment: PaymentOption): Promise<void>;
    getCost(key: string): Promise<string>;
}
