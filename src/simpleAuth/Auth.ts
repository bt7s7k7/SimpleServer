import { asError, delayedPromise } from "../comTypes/util"
import { DIService } from "../dependencyInjection/DIService"
import { EventEmitter } from "../eventLib/EventEmitter"
import { Struct } from "../struct/Struct"
import { Type } from "../struct/Type"
import { ActionType } from "../structSync/ActionType"
import { StructSyncClient } from "../structSync/StructSyncClient"
import { StructSyncContract } from "../structSync/StructSyncContract"
import { StructSyncMessages } from "../structSync/StructSyncMessages"
import { StructSyncServer } from "../structSync/StructSyncServer"

interface LoginResult<T> {
    user: T
    token: string
    refreshToken: string
}

function makeAuthContract<T>(userType: Type<T>) {
    const LoginResult_t = Type.object({
        user: userType,
        token: Type.string,
        refreshToken: Type.string
    })

    class Auth extends Struct.define("Auth", {}) { }
    return StructSyncContract.define(Auth, {
        login: ActionType.define("login", Type.object({ username: Type.string, password: Type.string }), LoginResult_t),
        register: ActionType.define("register", Type.object({ username: Type.string, password: Type.string }), LoginResult_t),
        refreshToken: ActionType.define("refreshToken", Type.object({ refreshToken: Type.string }), Type.object({ token: Type.string, refreshToken: Type.string })),
        getUser: ActionType.define("getUser", Type.empty, userType.as(Type.nullable))
    }, {})
}

class UserInvalidError extends Error {
    public readonly _isClientError = true
}

export namespace Auth {
    export function makeAuthController<T>(userType: Type<T>) {
        // @ts-ignore
        const bcryptjs = require("bcryptjs")
        // @ts-ignore
        const { randomBytes } = require("crypto")
        // @ts-ignore
        const jsonwebtoken = require("jsonwebtoken")
        const contract = makeAuthContract(userType)
        const userMeta = new WeakMap<StructSyncMessages.MetaHandle, T>()

        return class AuthController extends contract.defineController() {
            protected key = randomBytes(64)
            protected refreshKey = randomBytes(64)

            public async findUser(username: string) {
                return this.userMethods.findUser(username)?.user
            }

            public async makeTokens(username: string) {
                const token = await new Promise<string>((resolve, reject) => jsonwebtoken.sign({
                    sub: username,
                    iss: "auth"
                }, this.key, {
                    expiresIn: "1d"
                }, (err: any, token: string) => err ? reject(err) : resolve(token!)))

                const refreshToken = await new Promise<string>((resolve, reject) => jsonwebtoken.sign({
                    sub: username,
                    iss: "auth"
                }, this.refreshKey, {
                    expiresIn: "14d"
                }, (err: any, token: string) => err ? reject(err) : resolve(token!)))

                return { token, refreshToken }
            }

            public hashPassword(password: string, salt: string) {
                return bcryptjs.hashSync(password, salt)
            }

            public async verifyToken(token: string, type: "key" | "refreshKey"): Promise<string | null> {
                const payload = await new Promise<any>((resolve, reject) => jsonwebtoken.verify(
                    token, this[type], {},
                    (err: any, payload: any) => err ? reject(err) : resolve(payload!))).catch(() => null)

                if (!payload) return null
                if (payload.iss != "auth") return null

                return payload.sub!
            }

            public impl = super.impl({
                login: async ({ username, password }) => {
                    await delayedPromise(Math.floor(Math.random() * 10))

                    const entity = this.userMethods.findUser(username)
                    if (!entity) throw new UserInvalidError("User not found")

                    const passwordHash = this.hashPassword(password, entity.salt)
                    if (!this.userMethods.testUser(entity.user, passwordHash)) throw new UserInvalidError("User not found")

                    const keys = await this.makeTokens(username)

                    return { user: this.userMethods.sterilizeUser(entity.user), ...keys }
                },
                register: async ({ username, password }) => {
                    const alreadyUser = this.userMethods.findUser(username)
                    if (alreadyUser) throw new UserInvalidError("Username taken")

                    const salt = bcryptjs.genSaltSync()
                    const passwordHash = this.hashPassword(password, salt)
                    const user = this.userMethods.registerUser(username, passwordHash, salt)

                    const keys = await this.makeTokens(username)

                    return { user: this.userMethods.sterilizeUser(user), ...keys }
                },
                refreshToken: async ({ refreshToken }) => {
                    const username = await this.verifyToken(refreshToken, "refreshKey")
                    if (!username || !this.userMethods.findUser(username)) throw new UserInvalidError("Invalid token")

                    const keys = await this.makeTokens(username)
                    return keys
                },
                getUser: async (_, meta) => {
                    const user = AuthController.tryGetUser(meta)
                    if (user) return this.userMethods.sterilizeUser(user)
                    return null
                }
            })

            public readonly middleware = new class ServerMiddleware extends StructSyncServer.Middleware {
                constructor(
                    public readonly controller: AuthController
                ) {
                    super({
                        onIncoming: async (server, session, message, meta) => {
                            const token = message._token
                            if (token) {
                                const username = await this.controller.verifyToken(token, "key")
                                if (username) {
                                    const user = this.controller.userMethods.findUser(username)?.user
                                    if (user) userMeta.set(meta, user)
                                }
                            }
                        }
                    })
                }
            }(this)

            constructor(
                protected readonly userMethods: {
                    findUser: (username: string) => { user: T, salt: string } | null,
                    testUser: (user: T, passwordHash: string) => boolean,
                    registerUser: (username: string, passwordHash: string, salt: string) => T,
                    sterilizeUser: (user: T) => T
                }
            ) {
                super()
            }

            public static tryGetUser(meta: StructSyncMessages.MetaHandle) {
                return userMeta.get(meta) ?? null
            }

            public static getUser(meta: StructSyncMessages.MetaHandle) {
                const user = AuthController.tryGetUser(meta)
                if (!user) throw new UserInvalidError("Authentication required")
                return user
            }
        }
    }

    export function makeAuthBridge<T>(userType: Type<T>) {
        const contract = makeAuthContract(userType)


        class AuthProxy extends contract.defineProxy() { }

        return class AuthBridge extends DIService {
            public user: T | null = null
            public readonly onTokenChange = new EventEmitter<AuthBridge>()
            public readonly onUserChange = new EventEmitter<AuthBridge>()

            public readonly proxy = this.context.instantiate(() => AuthProxy.default())
            public readonly middleware = new class ClientMiddleware extends StructSyncClient.Middleware {
                constructor(
                    public readonly bridge: AuthBridge
                ) {
                    super({
                        onOutgoing: async (client, message) => {
                            if (this.bridge.token) {
                                return {
                                    ...message,
                                    _token: this.bridge.token
                                }
                            }
                        },
                    })
                }
            }(this)

            public async init() {
                if (this.token) {
                    const user = await this.proxy.getUser()
                    if (user) {
                        this.user = user
                        this.onUserChange.emit(this)
                        return
                    }

                    if (this.refreshToken) {
                        const tokens = await this.proxy.refreshToken({ refreshToken: this.refreshToken }).catch(asError)
                        if (tokens instanceof Error) {
                            if ((tokens as any).response?.data != "Invalid token") {
                                // eslint-disable-next-line no-console
                                console.error(tokens)
                            }
                            return
                        }
                        this.token = tokens.token
                        this.refreshToken = tokens.refreshToken
                        this.onTokenChange.emit(this)

                        const user = await this.proxy.getUser()
                        if (user) {
                            this.user = user
                            this.onUserChange.emit(this)
                        }
                    }
                }
            }

            public async login(username: string, password: string) {
                const { user, refreshToken, token } = await this.proxy.login({ username, password }) as unknown as LoginResult<T>

                this.user = user
                this.token = token
                this.refreshToken = refreshToken

                this.onTokenChange.emit(this)
                this.onUserChange.emit(this)
            }

            public async register(username: string, password: string) {
                const { user, refreshToken, token } = await this.proxy.register({ username, password }) as unknown as LoginResult<T>

                this.user = user
                this.token = token
                this.refreshToken = refreshToken

                this.onTokenChange.emit(this)
                this.onUserChange.emit(this)
            }

            public async logout() {
                this.user = null
                this.token = null
                this.refreshToken = null

                this.onTokenChange.emit(this)
                this.onUserChange.emit(this)
            }

            constructor(
                public token: string | null = null,
                public refreshToken: string | null = null
            ) { super() }
        }
    }
}