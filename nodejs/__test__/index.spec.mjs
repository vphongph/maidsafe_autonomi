import test from 'ava'

import { Client, Wallet, Network, PaymentOption } from '../index.js'

test('put chunk', async (t) => {
  const client = await Client.initLocal();
  const wallet = Wallet.newFromPrivateKey(new Network(true), "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

  const data = Buffer.from("hello world");
  const { cost, addr } = await client.chunkPut(data, PaymentOption.fromWallet(wallet));
  const dataRetrieved = await client.chunkGet(addr);
  
  t.deepEqual(data, dataRetrieved);
})
