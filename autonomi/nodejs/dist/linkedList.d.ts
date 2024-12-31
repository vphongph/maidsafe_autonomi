import { LinkedListOptions, PaymentOption } from './types';
export declare class LinkedList {
    private nativeList;
    private constructor();
    static create(address: string): Promise<LinkedList>;
    get(): Promise<any[]>;
    put(options: LinkedListOptions, payment: PaymentOption): Promise<void>;
    getCost(key: string): Promise<string>;
}
