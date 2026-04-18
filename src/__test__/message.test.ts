import { MessageType } from '../session-cipher'
import {
    completeHandshake,
    createUser,
    decodeEmbeddedWhisperMessage,
    decodeWhisperMessage,
    fromPlaintext,
    installDeterministicCrypto,
    toPlaintext,
    type DeterministicCryptoContext,
} from '../__test-utils__/protocol-test-utils'

jest.setTimeout(30000)

describe('message encryption and decryption', () => {
    let cryptoContext: DeterministicCryptoContext

    beforeEach(() => {
        cryptoContext = installDeterministicCrypto('message-suite')
    })

    afterEach(() => {
        cryptoContext.restore()
    })

    test('the first pre-key message decrypts correctly on the receiver', async () => {
        const alice = await createUser('alice-first-message')
        const bob = await createUser('bob-first-message')

        const exchange = await completeHandshake(
            alice,
            bob,
            {
                initial: 'hello from alice',
                reply: 'hello from bob',
            },
            {
                preKeyId: 21,
                signedPreKeyId: 1021,
            }
        )

        const embeddedWhisper = decodeEmbeddedWhisperMessage(exchange.ciphertext)

        expect(exchange.ciphertext.type).toBe(3)
        expect(embeddedWhisper.counter).toBe(0)
        expect(fromPlaintext(exchange.plaintext)).toBe('hello from alice')
        expect(fromPlaintext(exchange.replyPlaintext)).toBe('hello from bob')
    })

    test('multiple sequential whisper messages decrypt correctly in order', async () => {
        const alice = await createUser('alice-sequential')
        const bob = await createUser('bob-sequential')

        const handshake = await completeHandshake(
            alice,
            bob,
            {
                initial: 'bootstrap',
                reply: 'ready',
            },
            {
                preKeyId: 22,
                signedPreKeyId: 1022,
            }
        )

        const plaintexts = ['message one', 'message two', 'message three']
        const ciphertexts: MessageType[] = []

        for (const plaintext of plaintexts) {
            ciphertexts.push(await handshake.initiatorCipher.encrypt(toPlaintext(plaintext)))
        }

        const decrypted: string[] = []
        for (const ciphertext of ciphertexts) {
            expect(ciphertext.type).toBe(1)
            decrypted.push(
                fromPlaintext(await handshake.receiverCipher.decryptWhisperMessage(ciphertext.body!, 'binary'))
            )
        }

        expect(decrypted).toEqual(plaintexts)
    })

    test('encrypting the same plaintext twice uses different message keys', async () => {
        const alice = await createUser('alice-message-keys')
        const bob = await createUser('bob-message-keys')

        const handshake = await completeHandshake(
            alice,
            bob,
            {
                initial: 'bootstrap',
                reply: 'ready',
            },
            {
                preKeyId: 23,
                signedPreKeyId: 1023,
            }
        )

        const first = await handshake.initiatorCipher.encrypt(toPlaintext('same payload'))
        const second = await handshake.initiatorCipher.encrypt(toPlaintext('same payload'))

        const firstWhisper = decodeWhisperMessage(first)
        const secondWhisper = decodeWhisperMessage(second)

        expect(first.type).toBe(1)
        expect(second.type).toBe(1)
        expect(firstWhisper.counter).toBe(0)
        expect(secondWhisper.counter).toBe(1)
        expect(first.body).not.toBe(second.body)
        expect(Array.from(firstWhisper.ciphertext)).not.toEqual(Array.from(secondWhisper.ciphertext))
    })
})
