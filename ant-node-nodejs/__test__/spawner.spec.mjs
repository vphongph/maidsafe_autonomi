import test from 'ava'
import { Network, NetworkSpawner, NodeSpawner } from '../index.js'
import { setTimeout } from 'node:timers/promises';

test('construct NetworkSpawner', async (t) => {
    const networkSize = 20;

    const spawner = new NetworkSpawner({ local: true, noUpnp: true, size: networkSize });
    const runningNetwork = await spawner.spawn();

    const runningNodes = await runningNetwork.runningNodes();
    t.is(runningNodes.length, networkSize);

    // Wait for nodes to fill up their routing table
    console.log(`Waiting 15 seconds for ${networkSize} nodes to form network...`);
    await setTimeout(15 * 1000);

    console.log('\n=== Network Formation Report ===');
    const peerCounts = [];
    let failedNodes = [];
    let allPassed = true;

    // Validate that all nodes know each other
    for (const [index, node] of runningNodes.entries()) {
        const state = await node.getSwarmLocalState();
        const peersInRoutingTable = state.peersInRoutingTable;
        const connectedPeers = state.connectedPeers.length;
        const peerId = node.peerId();

        peerCounts.push(peersInRoutingTable);
        const passed = peersInRoutingTable >= networkSize - 2 && peersInRoutingTable < networkSize;

        if (!passed) {
            failedNodes.push({ index, peerId, peersInRoutingTable, connectedPeers });
            allPassed = false;
        }

        console.log(`Node ${index}: ${peersInRoutingTable} peers in RT, ${connectedPeers} connected ${passed ? '✓' : '✗'}`);
    }

    if (failedNodes.length > 0) {
        console.log('\n=== Failed Nodes ===');
        failedNodes.forEach(({ index, peerId, peersInRoutingTable, connectedPeers }) => {
            console.log(`Node ${index} (${peerId.substring(0, 12)}...): ${peersInRoutingTable} in RT (expected ${networkSize - 2}-${networkSize - 1}), ${connectedPeers} connected`);
        });
    }

    console.log('\n=== Statistics ===');
    console.log(`Min peers in RT: ${Math.min(...peerCounts)}`);
    console.log(`Max peers in RT: ${Math.max(...peerCounts)}`);
    console.log(`Avg peers in RT: ${(peerCounts.reduce((a, b) => a + b, 0) / peerCounts.length).toFixed(2)}`);
    console.log(`Expected range: ${networkSize - 2} to ${networkSize - 1}`);
    console.log(`Passed: ${runningNodes.length - failedNodes.length}/${runningNodes.length}`);
    console.log('================================\n');

    await runningNetwork.shutdown();

    // Assert the result
    t.true(allPassed, `${failedNodes.length} node(s) failed to reach expected peer count`);
});

test('construct NodeSpawner', async (t) => {
    const spawner = new NodeSpawner({ local: true }, Network.fromString('evm-arbitrum-one'));
    const runningNode = await spawner.spawn();
    runningNode.shutdown();

    t.true(typeof runningNode.peerId() === 'string' && runningNode.peerId().length > 0);
});
