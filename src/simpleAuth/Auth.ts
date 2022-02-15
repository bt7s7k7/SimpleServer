import { asError, delayedPromise, unreachable } from "../comTypes/util"
import { DIService } from "../dependencyInjection/DIService"
import { EventEmitter } from "../eventLib/EventEmitter"
import { Struct } from "../struct/Struct"
import { Type } from "../struct/Type"
import { ActionType } from "../structSync/ActionType"
import { StructSyncClient } from "../structSync/StructSyncClient"
import { StructSyncContract } from "../structSync/StructSyncContract"
import { StructSyncMessages } from "../structSync/StructSyncMessages"
import { ClientError, StructSyncServer } from "../structSync/StructSyncServer"
import { Permission, PermissionRepository } from "./PermissionRepository"

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
        getUser: ActionType.define("getUser", Type.empty, userType.as(Type.nullable)),
        changeOwnPassword: ActionType.define("changeOwnPassword", Type.object({ password: Type.string }), Type.empty),
        changePassword: ActionType.define("changePassword", Type.object({ username: Type.string, password: Type.string }), Type.empty),
        listUsers: ActionType.define("listUsers", Type.empty, userType.as(Type.array)),
        deleteOwnAccount: ActionType.define("deleteOwnAccount", Type.empty, Type.empty),
        deleteAccount: ActionType.define("deleteAccount", Type.object({ username: Type.string }), Type.empty)
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
            public key = randomBytes(64)
            public refreshKey = randomBytes(64)

            public async findUser(username: string) {
                return this.config.findUser(username)?.user
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

            public createAccount(username: string, password: string) {
                const duplicateUser = this.config.findUser(username)
                if (duplicateUser) throw new UserInvalidError("Username taken")

                const salt = bcryptjs.genSaltSync()
                const passwordHash = this.hashPassword(password, salt)
                return this.config.registerUser(username, passwordHash, salt)
            }

            public async resolveToken(token: string) {
                const username = await this.verifyToken(token, "key")
                if (username) {
                    const user = this.config.findUser(username)?.user
                    if (user) return user
                } else if (this.config.additionalTokenResolver) {
                    const user = this.config.additionalTokenResolver(token)
                    if (user) return user
                }

                return null
            }

            public impl = super.impl({
                login: async ({ username, password }) => {
                    await delayedPromise(Math.floor(Math.random() * 10))

                    const entity = this.config.findUser(username)
                    if (!entity) throw new UserInvalidError("User not found")

                    const passwordHash = this.hashPassword(password, entity.salt)
                    if (!this.config.testUser(entity.user, passwordHash)) throw new UserInvalidError("User not found")

                    const keys = await this.makeTokens(username)

                    return { user: this.config.sanitizeUser(entity.user), ...keys }
                },
                register: async ({ username, password }, meta) => {
                    if (this.config.disableRegistration) throw new ClientError("Registration is disabled")
                    this.config.permissions?.assertPermission(AuthController.PERMISSIONS.REGISTER, meta)

                    const user = this.createAccount(username, password)
                    const keys = await this.makeTokens(username)
                    return { user: this.config.sanitizeUser(user), ...keys }
                },
                refreshToken: async ({ refreshToken }) => {
                    const username = await this.verifyToken(refreshToken, "refreshKey")
                    if (!username || !this.config.findUser(username)) throw new UserInvalidError("Invalid token")

                    const keys = await this.makeTokens(username)
                    return keys
                },
                getUser: async (_, meta) => {
                    const user = AuthController.tryGetUser(meta)
                    if (user) return this.config.sanitizeUser(user)
                    return null
                },
                changeOwnPassword: async ({ password }, meta) => {
                    this.config.permissions?.assertPermission(AuthController.PERMISSIONS.CHANGE_OWN_PASSWORD, meta)
                    const user = AuthController.getUser(meta)
                    this.config.changeUserPassword(user, (salt) => this.hashPassword(password, salt))
                },
                changePassword: async ({ username, password }, meta) => {
                    if (this.config.permissions) this.config.permissions.assertPermission(AuthController.PERMISSIONS.CHANGE_PASSWORD, meta)
                    else throw new ClientError("Changing passwords is disabled")
                    const result = this.config.findUser(username)
                    if (!result) throw new ClientError("User not found")
                    this.config.changeUserPassword(result.user, (salt) => this.hashPassword(password, salt))
                },
                deleteOwnAccount: async (_, meta) => {
                    this.config.permissions?.assertPermission(AuthController.PERMISSIONS.DELETE_OWN_ACCOUNT, meta)
                    const user = AuthController.getUser(meta)
                    this.config.deleteUser(user)
                },
                deleteAccount: async ({ username }, meta) => {
                    if (this.config.permissions) this.config.permissions.assertPermission(AuthController.PERMISSIONS.DELETE_ACCOUNT, meta)
                    else throw new ClientError("Deleting users is disabled")
                    const result = this.config.findUser(username)
                    if (!result) throw new ClientError("User not found")
                    this.config.deleteUser(result.user)
                },
                listUsers: async (_, meta) => {
                    if (this.config.permissions) this.config.permissions.assertPermission(AuthController.PERMISSIONS.LIST_USERS, meta)
                    else throw new ClientError("Listing users is disabled")

                    return this.config.listUsers().map(this.config.sanitizeUser)
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
                                const user = await this.controller.resolveToken(token)
                                if (user) userMeta.set(meta, user)
                            }
                        }
                    })
                }
            }(this)

            constructor(
                protected readonly config: {
                    findUser: (username: string) => { user: T, salt: string } | null,
                    deleteUser: (user: T) => void,
                    testUser: (user: T, passwordHash: string) => boolean,
                    registerUser: (username: string, passwordHash: string, salt: string) => T,
                    changeUserPassword: (user: T, passwordHashFactory: (salt: string) => string) => void,
                    sanitizeUser: (user: T) => T,
                    listUsers: () => T[],
                    additionalTokenResolver?: (token: string) => T | null
                    disableRegistration?: boolean,
                    permissions?: PermissionRepository
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

            public static PERMISSIONS = {
                REGISTER: new Permission("auth.register"),
                CHANGE_OWN_PASSWORD: new Permission("auth.change_own_password"),
                CHANGE_PASSWORD: new Permission("auth.change_password"),
                LIST_USERS: new Permission("auth.list_users"),
                DELETE_OWN_ACCOUNT: new Permission("auth.delete_own_account"),
                DELETE_ACCOUNT: new Permission("auth.delete_account"),
            }

            public static DEFAULT_PERMISSIONS: PermissionRepository.PermissionEntry[] = [
                [AuthController.PERMISSIONS.REGISTER, () => true],
                [AuthController.PERMISSIONS.CHANGE_OWN_PASSWORD, "login"],
                [AuthController.PERMISSIONS.CHANGE_PASSWORD, () => false],
                [AuthController.PERMISSIONS.LIST_USERS, () => false],
                [AuthController.PERMISSIONS.DELETE_OWN_ACCOUNT, "login"],
                [AuthController.PERMISSIONS.DELETE_ACCOUNT, () => false],
            ]
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

                        return true
                    }

                    if (this.refreshToken) {
                        const tokens = await this.proxy.refreshToken({ refreshToken: this.refreshToken }).catch(asError)
                        if (tokens instanceof Error) {
                            if ((tokens as any).response?.data != "Invalid token") {
                                // eslint-disable-next-line no-console
                                console.error(tokens)
                            }

                            this.token = null
                            this.refreshToken = null
                            this.user = null
                            this.onTokenChange.emit(this)
                            this.onUserChange.emit(this)

                            return false
                        }
                        this.token = tokens.token
                        this.refreshToken = tokens.refreshToken
                        this.onTokenChange.emit(this)

                        const user = await this.proxy.getUser()
                        if (user) {
                            this.user = user
                            this.onUserChange.emit(this)

                            return true
                        }

                        throw unreachable()
                    } else {
                        this.token = null
                        this.refreshToken = null
                        this.user = null
                        this.onTokenChange.emit(this)
                        this.onUserChange.emit(this)

                        return false
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