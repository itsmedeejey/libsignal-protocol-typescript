import { PreKeyWhisperMessage, WhisperMessage } from '@privacyresearch/libsignal-protocol-protobuf-ts'

import * as Internal from '../internal'
import { arrayBufferToString, binaryStringToArrayBuffer, uint8ArrayToArrayBuffer } from '../helpers'
import { KeyHelper } from '../key-helper'
import { SessionCipher, MessageType } from '../session-cipher'
import { SessionRecord } from '../session-record'
import { SignalProtocolAddress } from '../signal-protocol-address'
import { SessionBuilder } from '../session-builder'
import { DeviceType, SessionType } from '../session-types'
import { Direction, KeyPairType, SessionRecordType, StorageType } from '../types'

function cloneArrayBuffer(value: ArrayBuffer): ArrayBuffer {
    return value.slice(0)
}

function cloneKeyPair(keyPair: KeyPairType<ArrayBuffer>): KeyPairType<ArrayBuffer> {
    return {
        pubKey: cloneArrayBuffer(keyPair.pubKey),
        privKey: cloneArrayBuffer(keyPair.privKey),
    }
}

export function arrayBufferEquals(left: ArrayBuffer, right: ArrayBuffer): boolean {
    if (left.byteLength !== right.byteLength) {
        return false
    }

    const a = new Uint8Array(left)
    const b = new Uint8Array(right)
    for (let index = 0; index < a.length; index += 1) {
        if (a[index] !== b[index]) {
            return false
        }
    }
    return true
}

function normalizeIdentityIdentifier(identifier: string): string {
    return identifier.includes('.') ? SignalProtocolAddress.fromString(identifier).getName() : identifier
}

function counterValue(map: Map<string, number>, key: string): number {
    return map.get(key) || 0
}

export class MockSignalProtocolStore implements StorageType {
    private identityKeyPair?: KeyPairType<ArrayBuffer>
    private registrationId?: number
    private identities = new Map<string, ArrayBuffer>()
    private preKeys = new Map<string, KeyPairType<ArrayBuffer>>()
    private signedPreKeys = new Map<string, KeyPairType<ArrayBuffer>>()
    private sessions = new Map<string, SessionRecordType>()

    readonly preKeyDeleteCounts = new Map<string, number>()
    readonly sessionStoreCounts = new Map<string, number>()
    readonly identitySaveCounts = new Map<string, number>()

    setLocalIdentity(identityKeyPair: KeyPairType<ArrayBuffer>, registrationId: number): void {
        this.identityKeyPair = cloneKeyPair(identityKeyPair)
        this.registrationId = registrationId
    }

    hasPreKey(keyId: number | string): boolean {
        return this.preKeys.has(String(keyId))
    }

    getPreKeyDeleteCount(keyId: number | string): number {
        return counterValue(this.preKeyDeleteCounts, String(keyId))
    }

    getSessionStoreCount(encodedAddress: string): number {
        return counterValue(this.sessionStoreCounts, encodedAddress)
    }

    getIdentitySaveCount(identifier: string): number {
        return counterValue(this.identitySaveCounts, normalizeIdentityIdentifier(identifier))
    }

    async getIdentityKeyPair(): Promise<KeyPairType<ArrayBuffer> | undefined> {
        return this.identityKeyPair ? cloneKeyPair(this.identityKeyPair) : undefined
    }

    async getLocalRegistrationId(): Promise<number | undefined> {
        return this.registrationId
    }

    async isTrustedIdentity(identifier: string, identityKey: ArrayBuffer, _direction: Direction): Promise<boolean> {
        const existing = this.identities.get(normalizeIdentityIdentifier(identifier))
        if (!existing) {
            return true
        }
        return arrayBufferEquals(existing, identityKey)
    }

    async saveIdentity(encodedAddress: string, publicKey: ArrayBuffer): Promise<boolean> {
        const identifier = normalizeIdentityIdentifier(encodedAddress)
        const previous = this.identities.get(identifier)
        this.identitySaveCounts.set(identifier, this.getIdentitySaveCount(identifier) + 1)
        this.identities.set(identifier, cloneArrayBuffer(publicKey))
        return !!previous && !arrayBufferEquals(previous, publicKey)
    }

    async loadPreKey(keyId: string | number): Promise<KeyPairType<ArrayBuffer> | undefined> {
        const keyPair = this.preKeys.get(String(keyId))
        return keyPair ? cloneKeyPair(keyPair) : undefined
    }

    async storePreKey(keyId: number | string, keyPair: KeyPairType<ArrayBuffer>): Promise<void> {
        this.preKeys.set(String(keyId), cloneKeyPair(keyPair))
    }

    async removePreKey(keyId: number | string): Promise<void> {
        const id = String(keyId)
        this.preKeyDeleteCounts.set(id, this.getPreKeyDeleteCount(id) + 1)
        this.preKeys.delete(id)
    }

    async storeSession(encodedAddress: string, record: SessionRecordType): Promise<void> {
        this.sessionStoreCounts.set(encodedAddress, this.getSessionStoreCount(encodedAddress) + 1)
        this.sessions.set(encodedAddress, record)
    }

    async loadSession(encodedAddress: string): Promise<SessionRecordType | undefined> {
        return this.sessions.get(encodedAddress)
    }

    async loadSignedPreKey(keyId: number | string): Promise<KeyPairType<ArrayBuffer> | undefined> {
        const keyPair = this.signedPreKeys.get(String(keyId))
        return keyPair ? cloneKeyPair(keyPair) : undefined
    }

    async storeSignedPreKey(keyId: number | string, keyPair: KeyPairType<ArrayBuffer>): Promise<void> {
        this.signedPreKeys.set(String(keyId), cloneKeyPair(keyPair))
    }

    async removeSignedPreKey(keyId: number | string): Promise<void> {
        this.signedPreKeys.delete(String(keyId))
    }

    async loadIdentityKey(identifier: string): Promise<ArrayBuffer | undefined> {
        const saved = this.identities.get(normalizeIdentityIdentifier(identifier))
        return saved ? cloneArrayBuffer(saved) : undefined
    }
}

export interface ProtocolUser {
    name: string
    address: SignalProtocolAddress
    store: MockSignalProtocolStore
    identityKeyPair: KeyPairType<ArrayBuffer>
    registrationId: number
}

export interface GeneratedPreKeyBundle {
    bundle: DeviceType<ArrayBuffer>
    preKeyId?: number
    preKeyPair?: KeyPairType<ArrayBuffer>
    signedPreKeyId: number
    signedPreKeyPair: KeyPairType<ArrayBuffer>
}

export interface PreKeyExchangeResult {
    bundleFixture: GeneratedPreKeyBundle
    initiatorCipher: SessionCipher
    receiverCipher: SessionCipher
    ciphertext: MessageType
    plaintext: ArrayBuffer
}

export interface CompletedHandshakeResult extends PreKeyExchangeResult {
    replyCiphertext: MessageType
    replyPlaintext: ArrayBuffer
}

export interface DeterministicCryptoContext {
    ecdhe: jest.SpyInstance<Promise<ArrayBuffer>, [pubKey: ArrayBuffer, privKey: ArrayBuffer]>
    getRandomBytes: jest.SpyInstance<ArrayBuffer, [n: number]>
    restore: () => void
}

function createMulberry32(seed: number): () => number {
    let state = seed >>> 0
    return () => {
        state = (state + 0x6d2b79f5) >>> 0
        let next = state
        next = Math.imul(next ^ (next >>> 15), next | 1)
        next ^= next + Math.imul(next ^ (next >>> 7), next | 61)
        return ((next ^ (next >>> 14)) >>> 0) / 4294967296
    }
}

function seedFromString(seed: string): number {
    let value = 1779033703
    for (let index = 0; index < seed.length; index += 1) {
        value = Math.imul(value ^ seed.charCodeAt(index), 3432918353)
        value = (value << 13) | (value >>> 19)
    }
    return value >>> 0
}

export function installDeterministicCrypto(seed = 'protocol-tests'): DeterministicCryptoContext {
    const random = createMulberry32(seedFromString(seed))

    const getRandomBytes = jest.spyOn(Internal.crypto, 'getRandomBytes').mockImplementation((length: number) => {
        const bytes = new Uint8Array(length)
        for (let index = 0; index < length; index += 1) {
            bytes[index] = Math.floor(random() * 256)
        }
        return uint8ArrayToArrayBuffer(bytes)
    })

    const ecdhe = jest.spyOn(Internal.crypto, 'ECDHE')
    return {
        ecdhe,
        getRandomBytes,
        restore: () => {
            ecdhe.mockRestore()
            getRandomBytes.mockRestore()
        },
    }
}

export async function createUser(name: string, deviceId = 1): Promise<ProtocolUser> {
    const store = new MockSignalProtocolStore()
    const identityKeyPair = await KeyHelper.generateIdentityKeyPair()
    const registrationId = KeyHelper.generateRegistrationId()
    store.setLocalIdentity(identityKeyPair, registrationId)

    return {
        name,
        address: new SignalProtocolAddress(name, deviceId),
        store,
        identityKeyPair,
        registrationId,
    }
}

export async function generatePreKeyBundle(
    user: ProtocolUser,
    options?: {
        includeOneTimePreKey?: boolean
        preKeyId?: number
        signedPreKeyId?: number
    }
): Promise<GeneratedPreKeyBundle> {
    const preKeyId = options?.preKeyId ?? 1
    const signedPreKeyId = options?.signedPreKeyId ?? 101
    const includeOneTimePreKey = options?.includeOneTimePreKey ?? true

    const signedPreKey = await KeyHelper.generateSignedPreKey(user.identityKeyPair, signedPreKeyId)
    await user.store.storeSignedPreKey(signedPreKeyId, signedPreKey.keyPair)

    let preKeyFixture: GeneratedPreKeyBundle['preKeyPair']
    if (includeOneTimePreKey) {
        const preKey = await KeyHelper.generatePreKey(preKeyId)
        preKeyFixture = preKey.keyPair
        await user.store.storePreKey(preKeyId, preKey.keyPair)
    }

    return {
        bundle: {
            identityKey: cloneArrayBuffer(user.identityKeyPair.pubKey),
            registrationId: user.registrationId,
            preKey: includeOneTimePreKey
                ? {
                      keyId: preKeyId,
                      publicKey: cloneArrayBuffer(preKeyFixture!.pubKey),
                  }
                : undefined,
            signedPreKey: {
                keyId: signedPreKeyId,
                publicKey: cloneArrayBuffer(signedPreKey.keyPair.pubKey),
                signature: cloneArrayBuffer(signedPreKey.signature),
            },
        },
        preKeyId: includeOneTimePreKey ? preKeyId : undefined,
        preKeyPair: preKeyFixture ? cloneKeyPair(preKeyFixture) : undefined,
        signedPreKeyId,
        signedPreKeyPair: cloneKeyPair(signedPreKey.keyPair),
    }
}

export function createSessionBuilder(localUser: ProtocolUser, remoteUser: ProtocolUser): SessionBuilder {
    return new SessionBuilder(localUser.store, remoteUser.address)
}

export function createSessionCipher(localUser: ProtocolUser, remoteUser: ProtocolUser): SessionCipher {
    return new SessionCipher(localUser.store, remoteUser.address)
}

export async function establishOutboundSession(
    initiator: ProtocolUser,
    receiver: ProtocolUser,
    options?: {
        includeOneTimePreKey?: boolean
        preKeyId?: number
        signedPreKeyId?: number
    }
): Promise<GeneratedPreKeyBundle> {
    const fixture = await generatePreKeyBundle(receiver, options)
    const builder = createSessionBuilder(initiator, receiver)
    await builder.processPreKey(fixture.bundle)
    return fixture
}

export async function performInitialPreKeyExchange(
    initiator: ProtocolUser,
    receiver: ProtocolUser,
    plaintext = 'initial pre-key message',
    options?: {
        includeOneTimePreKey?: boolean
        preKeyId?: number
        signedPreKeyId?: number
    }
): Promise<PreKeyExchangeResult> {
    const bundleFixture = await establishOutboundSession(initiator, receiver, options)
    const initiatorCipher = createSessionCipher(initiator, receiver)
    const receiverCipher = createSessionCipher(receiver, initiator)
    const ciphertext = await initiatorCipher.encrypt(toPlaintext(plaintext))
    const decrypted = await receiverCipher.decryptPreKeyWhisperMessage(ciphertext.body!, 'binary')

    return {
        bundleFixture,
        initiatorCipher,
        receiverCipher,
        ciphertext,
        plaintext: decrypted,
    }
}

export async function completeHandshake(
    initiator: ProtocolUser,
    receiver: ProtocolUser,
    messages?: {
        initial?: string
        reply?: string
    },
    options?: {
        includeOneTimePreKey?: boolean
        preKeyId?: number
        signedPreKeyId?: number
    }
): Promise<CompletedHandshakeResult> {
    const initial = messages?.initial ?? 'initial pre-key message'
    const reply = messages?.reply ?? 'reply from receiver'
    const exchange = await performInitialPreKeyExchange(initiator, receiver, initial, options)
    const replyCiphertext = await exchange.receiverCipher.encrypt(toPlaintext(reply))
    const replyPlaintext = await exchange.initiatorCipher.decryptWhisperMessage(replyCiphertext.body!, 'binary')

    return {
        ...exchange,
        replyCiphertext,
        replyPlaintext,
    }
}

export async function loadSessionRecord(
    store: MockSignalProtocolStore,
    remoteAddress: SignalProtocolAddress | string
): Promise<SessionRecord> {
    const encodedAddress = typeof remoteAddress === 'string' ? remoteAddress : remoteAddress.toString()
    const serialized = await store.loadSession(encodedAddress)
    if (!serialized) {
        throw new Error(`Missing session record for ${encodedAddress}`)
    }
    return SessionRecord.deserialize(serialized)
}

export async function loadOpenSession(
    store: MockSignalProtocolStore,
    remoteAddress: SignalProtocolAddress | string
): Promise<SessionType<ArrayBuffer>> {
    const record = await loadSessionRecord(store, remoteAddress)
    const session = record.getOpenSession()
    if (!session) {
        throw new Error(`Missing open session for ${typeof remoteAddress === 'string' ? remoteAddress : remoteAddress.toString()}`)
    }
    return session
}

export function toPlaintext(text: string): ArrayBuffer {
    return uint8ArrayToArrayBuffer(new TextEncoder().encode(text))
}

export function fromPlaintext(buffer: ArrayBuffer): string {
    return new TextDecoder().decode(new Uint8Array(buffer))
}

function requireBody(message: MessageType | string): string {
    const body = typeof message === 'string' ? message : message.body
    if (!body) {
        throw new Error('Message body is missing')
    }
    return body
}

export function decodePreKeyMessage(message: MessageType | string): PreKeyWhisperMessage {
    const body = requireBody(message)
    const encoded = new Uint8Array(binaryStringToArrayBuffer(body))
    return PreKeyWhisperMessage.decode(encoded.slice(1))
}

export function decodeWhisperMessage(message: MessageType | string): WhisperMessage {
    const body = requireBody(message)
    const encoded = new Uint8Array(binaryStringToArrayBuffer(body))
    return WhisperMessage.decode(encoded.slice(1, encoded.byteLength - 8))
}

export function decodeEmbeddedWhisperMessage(message: MessageType | string): WhisperMessage {
    const preKeyMessage = decodePreKeyMessage(message)
    const encoded = preKeyMessage.message
    return WhisperMessage.decode(encoded.slice(1, encoded.byteLength - 8))
}

export function buildPreKeyMessageForSession(
    initiator: ProtocolUser,
    session: SessionType<ArrayBuffer>,
    signedPreKeyId: number
): PreKeyWhisperMessage {
    if (!session.pendingPreKey) {
        throw new Error('Session is missing pending pre-key metadata')
    }

    const message = PreKeyWhisperMessage.fromJSON({})
    message.identityKey = new Uint8Array(initiator.identityKeyPair.pubKey)
    message.registrationId = initiator.registrationId
    message.baseKey = new Uint8Array(session.pendingPreKey.baseKey)
    message.signedPreKeyId = signedPreKeyId
    if (session.pendingPreKey.preKeyId !== undefined) {
        message.preKeyId = session.pendingPreKey.preKeyId
    }
    message.message = new Uint8Array(0)
    return message
}

export function tamperMessageBody(body: string, indexFromStart = 1): string {
    const bytes = new Uint8Array(binaryStringToArrayBuffer(body))
    const index = indexFromStart >= 0 ? indexFromStart : bytes.length + indexFromStart
    if (index <= 0 || index >= bytes.length) {
        throw new Error(`Tamper index ${indexFromStart} is out of bounds for ${bytes.length} bytes`)
    }
    bytes[index] ^= 0xff
    return arrayBufferToString(bytes.buffer)
}
