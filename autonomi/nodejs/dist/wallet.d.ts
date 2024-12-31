import { NetworkConfig } from './types';
export interface WalletConfig {
    privateKey?: string;
    address?: string;
}
export declare class Wallet {
    private nativeWallet;
    private constructor();
    static create(config: NetworkConfig & WalletConfig): Promise<Wallet>;
    getAddress(): Promise<string>;
    getBalance(): Promise<string>;
    signMessage(message: string): Promise<string>;
}
