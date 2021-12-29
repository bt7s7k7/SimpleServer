import { Struct } from "../struct/Struct"
import { Type } from "../struct/Type"

type EntityType<T extends SimpleDBOptions, K extends keyof T["tables"]> = InstanceType<T["tables"][K]>

interface SimpleDBOptions {
    tables: Record<string, Struct.StructConcept<Record<string, Type<any>>>>
    onChanged?: () => void
}

interface SimpleDBData {
    tables: Record<string, Record<string, any>>
}

export class SimpleDB<T extends SimpleDBOptions = SimpleDBOptions> {
    protected readonly tables = new Map<keyof T["tables"], Map<string, Struct.StructBase>>()
    public dirty = false

    public put<K extends keyof T["tables"]>(table: K, data: EntityType<T, K>) {
        this.tables.get(table)!.set(data.id ?? "sigleton", data)
        this.dirty = true
        this.options.onChanged?.()
    }

    public delete<K extends keyof T["tables"]>(table: K, id?: string) {
        const deleted = this.tables.get(table)!.delete(id ?? "sigleton")

        if (deleted) {
            this.dirty = true
            this.options.onChanged?.()
        }

        return deleted
    }

    public tryGet<K extends keyof T["tables"]>(table: K, id?: string): EntityType<T, K> | null {
        return (this.tables.get(table)!.get(id ?? "sigleton") ?? null) as EntityType<T, K> | null
    }

    public get<K extends keyof T["tables"]>(table: K, id?: string) {
        const ret = this.tryGet(table, id)
        if (!ret) throw new RangeError(`Cannot get entity with id "${id}"`)
        return ret
    }

    public list<K extends keyof T["tables"]>(table: K): IterableIterator<EntityType<T, K>> {
        return this.tables.get(table)!.values() as IterableIterator<EntityType<T, K>>
    }

    public export() {
        const result: SimpleDBData = {
            tables: {}
        }

        for (const [key, table] of this.tables) {
            result.tables[key as string] = {}
            const tableData = result.tables[key as string]
            for (const [id, value] of table) {
                tableData[id] = value.serialize()
            }
        }

        return result
    }

    public import(data: SimpleDBData) {
        for (const [key, tableData] of Object.entries(data.tables)) {
            const table = this.tables.get(key)!
            for (const [id, entityData] of Object.entries(tableData)) {
                table.set(id, this.options.tables[key].deserialize(entityData))
            }
        }
    }

    public entityChanged() {
        this.dirty = true
        this.options.onChanged?.()
    }

    constructor(
        protected readonly options: T
    ) {
        for (const key of Object.keys(options.tables)) {
            this.tables.set(key, new Map())
        }
    }
}

