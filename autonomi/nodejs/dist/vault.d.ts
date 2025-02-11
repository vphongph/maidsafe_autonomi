import { VaultOptions, PaymentOption, UserData } from './types';
export declare class Vault {
    private nativeVault;
    private constructor();
    static create(address: string): Promise<Vault>;
    getCost(key: string): Promise<string>;
    writeBytes(data: Buffer, payment: PaymentOption, options: VaultOptions): Promise<string>;
    fetchAndDecrypt(key: string): Promise<[Buffer, number]>;
    getUserData(key: string): Promise<UserData>;
    putUserData(key: string, payment: PaymentOption, userData: UserData): Promise<void>;
}
