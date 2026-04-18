import * as base64 from 'base64-js'
import { PreKeyWhisperMessage } from '@privacyresearch/libsignal-protocol-protobuf-ts'

import * as Internal from '../internal'
import { uint8ArrayToArrayBuffer } from '../helpers'
import { ChainType, SessionType } from '../session-types'
import {
    arrayBufferEquals,
    completeHandshake,
    createSessionBuilder,
    createUser,
    decodeWhisperMessage,
    fromPlaintext,
    generatePreKeyBundle,
    installDeterministicCrypto,
    loadOpenSession,
    performInitialPreKeyExchange,
    toPlaintext,
    type DeterministicCryptoContext,
} from '../__test-utils__/protocol-test-utils'

jest.setTimeout(30000)

function getCurrentSendingChain(session: SessionType<ArrayBuffer>) {
    if (!session.currentRatchet.ephemeralKeyPair) {
        throw new Error('Current ratchet is missing an ephemeral key pair')
    }

    const key = base64.fromByteArray(new Uint8Array(session.currentRatchet.ephemeralKeyPair.pubKey))
    return session.chains[key]
}

describe('double ratchet behavior', () => {
    let cryptoContext: DeterministicCryptoContext

    beforeEach(() => {
        cryptoContext = installDeterministicCrypto('ratchet-suite')
    })

    afterEach(() => {
        cryptoContext.restore()
    })

    test('calculateSendingRatchet creates a sending chain and updates the root key', async () => {
        const alice = await createUser('alice-calculate-ratchet')
        const bob = await createUser('bob-calculate-ratchet')
        const bundleFixture = await generatePreKeyBundle(bob, { preKeyId: 31, signedPreKeyId: 1031 })

        const aliceBaseKey = await Internal.crypto.createKeyPair()
        const bobBuilder = createSessionBuilder(bob, alice)
        const preKeyMessage = PreKeyWhisperMessage.fromJSON({})
        preKeyMessage.identityKey = new Uint8Array(alice.identityKeyPair.pubKey)
        preKeyMessage.registrationId = alice.registrationId
        preKeyMessage.baseKey = new Uint8Array(aliceBaseKey.pubKey)
        preKeyMessage.signedPreKeyId = bundleFixture.signedPreKeyId
        if (bundleFixture.preKeyId !== undefined) {
            preKeyMessage.preKeyId = bundleFixture.preKeyId
        }
        preKeyMessage.message = new Uint8Array(0)

        const session = await bobBuilder.startSessionWthPreKeyMessage(
            bundleFixture.preKeyPair,
            bundleFixture.signedPreKeyPair,
            preKeyMessage
        )

        const previousRootKey = session.currentRatchet.rootKey
        await bobBuilder.calculateSendingRatchet(session, (await Internal.crypto.createKeyPair()).pubKey)

        const sendingChain = getCurrentSendingChain(session)

        expect(sendingChain).toBeDefined()
        expect(sendingChain.chainType).toBe(ChainType.SENDING)
        expect(sendingChain.chainKey.counter).toBe(-1)
        expect(arrayBufferEquals(previousRootKey, session.currentRatchet.rootKey)).toBe(false)
        expect(cryptoContext.ecdhe).toHaveBeenCalled()
    })

    test('the sending chain key advances for every encrypted message', async () => {
        const alice = await createUser('alice-sending-chain')
        const bob = await createUser('bob-sending-chain')
        const handshake = await completeHandshake(
            alice,
            bob,
            {
                initial: 'bootstrap',
                reply: 'reply to clear pending pre-key',
            },
            {
                preKeyId: 32,
                signedPreKeyId: 1032,
            }
        )

        const initialChain = getCurrentSendingChain(await loadOpenSession(alice.store, bob.address))
        const initialKey = initialChain.chainKey.key
        expect(initialChain.chainKey.counter).toBe(-1)

        await handshake.initiatorCipher.encrypt(toPlaintext('message 1'))
        const afterFirst = getCurrentSendingChain(await loadOpenSession(alice.store, bob.address))

        await handshake.initiatorCipher.encrypt(toPlaintext('message 2'))
        const afterSecond = getCurrentSendingChain(await loadOpenSession(alice.store, bob.address))

        expect(afterFirst.chainKey.counter).toBe(0)
        expect(afterSecond.chainKey.counter).toBe(1)
        expect(arrayBufferEquals(initialKey!, afterFirst.chainKey.key!)).toBe(false)
        expect(arrayBufferEquals(afterFirst.chainKey.key!, afterSecond.chainKey.key!)).toBe(false)
    })

    test('a ratchet step updates the root key and a new remote ephemeral creates new chains', async () => {
        const alice = await createUser('alice-ratchet-step')
        const bob = await createUser('bob-ratchet-step')
        const exchange = await performInitialPreKeyExchange(alice, bob, 'bootstrap', {
            preKeyId: 33,
            signedPreKeyId: 1033,
        })

        const aliceBeforeReply = await loadOpenSession(alice.store, bob.address)
        const previousRootKey = aliceBeforeReply.currentRatchet.rootKey
        const previousSendingEphemeral = aliceBeforeReply.currentRatchet.ephemeralKeyPair!.pubKey

        const replyCiphertext = await exchange.receiverCipher.encrypt(toPlaintext('ratchet reply'))
        const replyWhisper = decodeWhisperMessage(replyCiphertext)
        const replyEphemeralKey = uint8ArrayToArrayBuffer(replyWhisper.ephemeralKey)
        const plaintext = await exchange.initiatorCipher.decryptWhisperMessage(replyCiphertext.body!, 'binary')
        const aliceAfterReply = await loadOpenSession(alice.store, bob.address)

        const newSendingEphemeral = aliceAfterReply.currentRatchet.ephemeralKeyPair!.pubKey
        const receivingChainKey = base64.fromByteArray(new Uint8Array(replyEphemeralKey))
        const sendingChainKey = base64.fromByteArray(new Uint8Array(newSendingEphemeral))

        expect(fromPlaintext(plaintext)).toBe('ratchet reply')
        expect(arrayBufferEquals(previousRootKey, aliceAfterReply.currentRatchet.rootKey)).toBe(false)
        expect(arrayBufferEquals(previousSendingEphemeral, newSendingEphemeral)).toBe(false)
        expect(arrayBufferEquals(aliceAfterReply.currentRatchet.lastRemoteEphemeralKey, replyEphemeralKey)).toBe(true)
        expect(aliceAfterReply.chains[receivingChainKey]?.chainType).toBe(ChainType.RECEIVING)
        expect(aliceAfterReply.chains[sendingChainKey]?.chainType).toBe(ChainType.SENDING)
    })
})
