import { StructSyncMessages } from "../structSync/StructSyncMessages"
import { ClientError } from "../structSync/StructSyncServer"
import { Auth } from "./Auth"

export class PermissionRepository {
    protected permissionRequirements

    public hasPermission(permission: Permission, meta: StructSyncMessages.MetaHandle) {
        const requiremenet = this.permissionRequirements.get(permission)
        if (!requiremenet) throw new Error("Cannot find requirement for permission " + permission.label)

        if (requiremenet == "login") {
            this.controller.getUser(meta)
            return true
        }

        return requiremenet(meta)
    }

    public assertPermission(permission: Permission, meta: StructSyncMessages.MetaHandle) {
        if (!this.hasPermission(permission, meta)) throw new ClientError("Not enough permission")
    }

    constructor(
        protected readonly controller: Omit<ReturnType<typeof Auth["makeAuthController"]>, "config">,
        requirements: PermissionRepository.PermissionEntry[]
    ) {
        this.permissionRequirements = new Map(requirements)
    }
}

export namespace PermissionRepository {
    export type PermissionRequirement = "login" | ((meta: StructSyncMessages.MetaHandle) => boolean)
    export type PermissionEntry = [Permission, PermissionRepository.PermissionRequirement]
}

export class Permission {
    constructor(public readonly label: string) { }
}