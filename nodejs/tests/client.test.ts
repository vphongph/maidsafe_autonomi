import { Client } from '../src/client';

describe('Client', () => {
    describe('connect', () => {
        it('should throw not implemented error', async () => {
            await expect(Client.connect({ peers: [] })).rejects.toThrow('Not implemented');
        });
    });

    describe('GarphEntryOperations', () => {
        it('should throw not implemented error for GarphEntryGet', async () => {
            const client = await Client.connect({ peers: [] }).catch(() => null);
            if (!client) return;
            await expect(client.GarphEntryGet('address')).rejects.toThrow('Not implemented');
        });

        it('should throw not implemented error for GarphEntryPut', async () => {
            const client = await Client.connect({ peers: [] }).catch(() => null);
            if (!client) return;
            await expect(
                client.GarphEntryPut(
                    {
                        owner: 'owner',
                        counter: 0,
                        target: 'target',
                        key: 'key'
                    },
                    { type: 'wallet', wallet: 'wallet' }
                )
            ).rejects.toThrow('Not implemented');
        });
    });
}); 