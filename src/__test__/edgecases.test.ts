import { KeyHelper } from '../key-helper'
import {
    completeHandshake,
    createSessionBuilder,
    createSessionCipher,
    createUser,
    establishOutboundSession,
    fromPlaintext,
    generatePreKeyBundle,
    installDeterministicCrypto,
    tamperMessageBody,
    toPlaintext,
    type DeterministicCryptoContext,
} from '../__test-utils__/protocol-test-utils'

jest.setTimeout(30000)

describe('edge cases and concurrency', () => {
    let cryptoContext: DeterministicCryptoContext

    beforeEach(() => {
        cryptoContext = installDeterministicCrypto('edge-suite')
    })

    afterEach(() => {
        cryptoContext.restore()
    })

    test('an unexpected identity key is rejected during session setup', async () => {
        const alice = await createUser('alice-trust')
        const bob = await createUser('bob-trust')
        await establishOutboundSession(alice, bob, { preKeyId: 41, signedPreKeyId: 1041 })

        const rogue = await createUser('mallory-trust')
        const rogueSignedPreKey = await KeyHelper.generateSignedPreKey(rogue.identityKeyPair, 2041)
        const roguePreKey = await KeyHelper.generatePreKey(3041)

        await expect(
            createSessionBuilder(alice, bob).processPreKey({
                identityKey: rogue.identityKeyPair.pubKey,
                registrationId: rogue.registrationId,
                preKey: {
                    keyId: roguePreKey.keyId,
                    publicKey: roguePreKey.keyPair.pubKey,
                },
                signedPreKey: {
                    keyId: rogueSignedPreKey.keyId,
                    publicKey: rogueSignedPreKey.keyPair.pubKey,
                    signature: rogueSignedPreKey.signature,
                },
            })
        ).rejects.toThrow('Identity key changed')
    })

    test('corrupted ciphertext fails decryption', async () => {
        const alice = await createUser('alice-corrupt')
        const bob = await createUser('bob-corrupt')
        const handshake = await completeHandshake(
            alice,
            bob,
            {
                initial: 'bootstrap',
                reply: 'ready',
            },
            {
                preKeyId: 42,
                signedPreKeyId: 1042,
            }
        )

        const message = await handshake.initiatorCipher.encrypt(toPlaintext('tamper me'))
        const tamperedBody = tamperMessageBody(message.body!, -1)

        await expect(handshake.receiverCipher.decryptWhisperMessage(tamperedBody, 'binary')).rejects.toThrow('Bad MAC')
    })

    test('duplicate whisper messages are rejected after the first successful decrypt', async () => {
        const alice = await createUser('alice-duplicate')
        const bob = await createUser('bob-duplicate')
        const handshake = await completeHandshake(
            alice,
            bob,
            {
                initial: 'bootstrap',
                reply: 'ready',
            },
            {
                preKeyId: 43,
                signedPreKeyId: 1043,
            }
        )

        const message = await handshake.initiatorCipher.encrypt(toPlaintext('deliver once'))
        const plaintext = await handshake.receiverCipher.decryptWhisperMessage(message.body!, 'binary')

        expect(fromPlaintext(plaintext)).toBe('deliver once')
        await expect(handshake.receiverCipher.decryptWhisperMessage(message.body!, 'binary')).rejects.toHaveProperty(
            'name',
            'MessageCounterError'
        )
    })

    test('out-of-order whisper messages are decrypted when skipped message keys are available', async () => {
        const alice = await createUser('alice-out-of-order')
        const bob = await createUser('bob-out-of-order')
        const handshake = await completeHandshake(
            alice,
            bob,
            {
                initial: 'bootstrap',
                reply: 'ready',
            },
            {
                preKeyId: 44,
                signedPreKeyId: 1044,
            }
        )

        const first = await handshake.initiatorCipher.encrypt(toPlaintext('first'))
        const second = await handshake.initiatorCipher.encrypt(toPlaintext('second'))

        const secondPlaintext = await handshake.receiverCipher.decryptWhisperMessage(second.body!, 'binary')
        const firstPlaintext = await handshake.receiverCipher.decryptWhisperMessage(first.body!, 'binary')

        expect(fromPlaintext(secondPlaintext)).toBe('second')
        expect(fromPlaintext(firstPlaintext)).toBe('first')
    })

    test('simultaneous pre-key deliveries do not race OPK consumption', async () => {
        const alice = await createUser('alice-concurrency')
        const bob = await createUser('bob-concurrency')
        const bundleFixture = await generatePreKeyBundle(bob, { preKeyId: 45, signedPreKeyId: 1045 })
        await createSessionBuilder(alice, bob).processPreKey(bundleFixture.bundle)

        const aliceCipher = createSessionCipher(alice, bob)
        const bobCipher = createSessionCipher(bob, alice)
        const first = await aliceCipher.encrypt(toPlaintext('concurrent one'))
        const second = await aliceCipher.encrypt(toPlaintext('concurrent two'))

        const [firstPlaintext, secondPlaintext] = await Promise.all([
            bobCipher.decryptPreKeyWhisperMessage(first.body!, 'binary'),
            bobCipher.decryptPreKeyWhisperMessage(second.body!, 'binary'),
        ])

        expect(fromPlaintext(firstPlaintext)).toBe('concurrent one')
        expect(fromPlaintext(secondPlaintext)).toBe('concurrent two')
        expect(bob.store.hasPreKey(bundleFixture.preKeyId!)).toBe(false)
        expect(bob.store.getPreKeyDeleteCount(bundleFixture.preKeyId!)).toBeGreaterThan(0)
    })
})
