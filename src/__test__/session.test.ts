import { PreKeyWhisperMessage } from '@privacyresearch/libsignal-protocol-protobuf-ts'

import * as Internal from '../internal'
import { uint8ArrayToArrayBuffer } from '../helpers'
import { SessionRecord } from '../session-record'
import {
    arrayBufferEquals,
    createSessionBuilder,
    createSessionCipher,
    createUser,
    decodePreKeyMessage,
    fromPlaintext,
    generatePreKeyBundle,
    installDeterministicCrypto,
    loadOpenSession,
    loadSessionRecord,
    performInitialPreKeyExchange,
    toPlaintext,
    type DeterministicCryptoContext,
} from '../__test-utils__/protocol-test-utils'

jest.setTimeout(30000)

describe('session establishment', () => {
    let cryptoContext: DeterministicCryptoContext

    beforeEach(() => {
        cryptoContext = installDeterministicCrypto('session-suite')
    })

    afterEach(() => {
        cryptoContext.restore()
    })

    test('both sides derive the same X3DH master root before the initiator sending ratchet advances it', async () => {
        const alice = await createUser('alice-root')
        const bob = await createUser('bob-root')
        const bundleFixture = await generatePreKeyBundle(bob, { preKeyId: 11, signedPreKeyId: 1011 })

        const aliceBaseKey = await Internal.crypto.createKeyPair()
        const aliceIdentity = await alice.store.getIdentityKeyPair()
        const aliceBuilder = createSessionBuilder(alice, bob)
        const aliceSession = await aliceBuilder.startSessionAsInitiator(
            aliceBaseKey,
            bundleFixture.bundle.identityKey,
            bundleFixture.bundle.signedPreKey.publicKey,
            bundleFixture.bundle.preKey?.publicKey,
            bundleFixture.bundle.registrationId
        )

        const preKeyMessage = PreKeyWhisperMessage.fromJSON({})
        preKeyMessage.identityKey = new Uint8Array(alice.identityKeyPair.pubKey)
        preKeyMessage.registrationId = alice.registrationId
        preKeyMessage.baseKey = new Uint8Array(aliceBaseKey.pubKey)
        preKeyMessage.signedPreKeyId = bundleFixture.signedPreKeyId
        if (bundleFixture.preKeyId !== undefined) {
            preKeyMessage.preKeyId = bundleFixture.preKeyId
        }
        preKeyMessage.message = new Uint8Array(0)

        const bobBuilder = createSessionBuilder(bob, alice)
        const bobSession = await bobBuilder.startSessionWthPreKeyMessage(
            bundleFixture.preKeyPair,
            bundleFixture.signedPreKeyPair,
            preKeyMessage
        )

        const sharedSecret = new Uint8Array(32 * 5)
        sharedSecret.fill(0xff, 0, 32)
        const [dh1, dh2, dh3, dh4] = await Promise.all([
            Internal.crypto.ECDHE(bundleFixture.bundle.signedPreKey.publicKey, aliceIdentity!.privKey),
            Internal.crypto.ECDHE(bundleFixture.bundle.identityKey, aliceBaseKey.privKey),
            Internal.crypto.ECDHE(bundleFixture.bundle.signedPreKey.publicKey, aliceBaseKey.privKey),
            Internal.crypto.ECDHE(bundleFixture.bundle.preKey!.publicKey, aliceBaseKey.privKey),
        ])
        sharedSecret.set(new Uint8Array(dh1), 32)
        sharedSecret.set(new Uint8Array(dh2), 64)
        sharedSecret.set(new Uint8Array(dh3), 96)
        sharedSecret.set(new Uint8Array(dh4), 128)
        const [expectedInitialRootKey] = await Internal.HKDF(sharedSecret.buffer, new ArrayBuffer(32), 'WhisperText')

        expect(arrayBufferEquals(expectedInitialRootKey, bobSession.currentRatchet.rootKey)).toBe(true)
        expect(arrayBufferEquals(expectedInitialRootKey, aliceSession.currentRatchet.rootKey)).toBe(false)
        expect(cryptoContext.ecdhe).toHaveBeenCalled()
    })

    test('processV3 derives the inbound session and defers persistence until decrypt succeeds', async () => {
        const alice = await createUser('alice-process-v3')
        const bob = await createUser('bob-process-v3')
        const bundleFixture = await generatePreKeyBundle(bob, { preKeyId: 12, signedPreKeyId: 1012 })

        const aliceBuilder = createSessionBuilder(alice, bob)
        await aliceBuilder.processPreKey(bundleFixture.bundle)
        const aliceSession = await loadOpenSession(alice.store, bob.address)

        const aliceCipher = createSessionCipher(alice, bob)
        const preKeyCiphertext = await aliceCipher.encrypt(toPlaintext('process-v3 handshake'))
        const preKeyMessage = decodePreKeyMessage(preKeyCiphertext)

        const record = new SessionRecord()
        const bobBuilder = createSessionBuilder(bob, alice)
        const result = await bobBuilder.processV3(record, preKeyMessage)
        const bobSession = result.session

        expect(result.preKeyId).toBe(bundleFixture.preKeyId)
        expect(result.identityKey).toBeDefined()
        expect(record.getSessionByBaseKey(uint8ArrayToArrayBuffer(preKeyMessage.baseKey))).toBeUndefined()
        expect(arrayBufferEquals(result.identityKey!, alice.identityKeyPair.pubKey)).toBe(true)
        expect(arrayBufferEquals(bobSession.indexInfo.remoteIdentityKey, alice.identityKeyPair.pubKey)).toBe(true)
        expect(arrayBufferEquals(aliceSession.pendingPreKey!.baseKey, uint8ArrayToArrayBuffer(preKeyMessage.baseKey))).toBe(
            true
        )
        expect(bob.store.hasPreKey(bundleFixture.preKeyId!)).toBe(true)
        expect(bob.store.getPreKeyDeleteCount(bundleFixture.preKeyId!)).toBe(0)
    })

    test('full pre-key establishment persists and reloads across new SessionCipher instances', async () => {
        const alice = await createUser('alice-persist')
        const bob = await createUser('bob-persist')

        const exchange = await performInitialPreKeyExchange(alice, bob, 'bootstrap session', {
            preKeyId: 13,
            signedPreKeyId: 1013,
        })

        expect(exchange.ciphertext.type).toBe(3)
        expect(fromPlaintext(exchange.plaintext)).toBe('bootstrap session')

        const aliceRecord = await loadSessionRecord(alice.store, bob.address)
        const bobRecord = await loadSessionRecord(bob.store, alice.address)
        expect(aliceRecord.haveOpenSession()).toBe(true)
        expect(bobRecord.haveOpenSession()).toBe(true)

        const reloadedAliceCipher = createSessionCipher(alice, bob)
        const reloadedBobCipher = createSessionCipher(bob, alice)
        const reply = await reloadedBobCipher.encrypt(toPlaintext('persisted reply'))
        const plaintext = await reloadedAliceCipher.decryptWhisperMessage(reply.body!, 'binary')

        expect(reply.type).toBe(1)
        expect(fromPlaintext(plaintext)).toBe('persisted reply')
        expect(alice.store.getSessionStoreCount(bob.address.toString())).toBeGreaterThan(0)
        expect(bob.store.getSessionStoreCount(alice.address.toString())).toBeGreaterThan(0)
    })

    test('session establishment falls back to the signed pre-key when no OPK is advertised', async () => {
        const alice = await createUser('alice-no-opk')
        const bob = await createUser('bob-no-opk')

        const exchange = await performInitialPreKeyExchange(alice, bob, 'signed pre-key only', {
            includeOneTimePreKey: false,
            signedPreKeyId: 1014,
        })

        expect(exchange.bundleFixture.preKeyId).toBeUndefined()
        expect(exchange.ciphertext.type).toBe(3)
        expect(fromPlaintext(exchange.plaintext)).toBe('signed pre-key only')
    })

    test('reusing a consumed OPK with a fresh pre-key message fails', async () => {
        const alice = await createUser('alice-stale-opk')
        const bob = await createUser('bob-stale-opk')

        const exchange = await performInitialPreKeyExchange(alice, bob, 'first use', {
            preKeyId: 14,
            signedPreKeyId: 1015,
        })

        const staleBuilder = createSessionBuilder(alice, bob)
        await staleBuilder.processPreKey(exchange.bundleFixture.bundle)

        const staleCipher = createSessionCipher(alice, bob)
        const staleMessage = await staleCipher.encrypt(toPlaintext('reuse consumed opk'))

        await expect(
            createSessionCipher(bob, alice).decryptPreKeyWhisperMessage(staleMessage.body!, 'binary')
        ).rejects.toThrow('Missing OPK for incoming message')

        expect(bob.store.hasPreKey(exchange.bundleFixture.preKeyId!)).toBe(false)
    })
})
