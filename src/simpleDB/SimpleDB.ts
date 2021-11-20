import { Struct } from "../struct/Struct"
import { Type } from "../struct/Type"

type FilterProps<T> = Pick<T, keyof T>

interface SimpleDBOptions {
    tables: Record<string, FilterProps<Struct.TypedStruct<Type.ObjectType<{ id: Type<string> }>>> & { new(source: any): any }>
}

interface SimpleDBData {
    tables: Record<string, Record<string, any>>
}

export class SimpleDB<T extends SimpleDBOptions = SimpleDBOptions> {
    protected readonly tables = new Map<keyof T["tables"], Map<string, Struct.StructBase>>()

    public put<K extends keyof T["tables"]>(table: K, data: InstanceType<T["tables"][K]>) {
        this.tables.get(table)!.set(data.id, data)
    }

    public tryGet<K extends keyof T["tables"]>(table: K, id: string) {
        return this.tables.get(table)!.get(id) ?? null as InstanceType<T["tables"][K]> | null
    }

    public get<K extends keyof T["tables"]>(table: K, id: string) {
        const ret = this.tryGet(table, id)
        if (!ret) throw new RangeError(`Cannot get entity with id "${id}"`)
        return ret
    }

    public list<K extends keyof T["tables"]>(table: K) {
        return this.tables.get(table)!.values() as IterableIterator<InstanceType<T["tables"][K]>>
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

    constructor(
        protected readonly options: T
    ) {
        for (const key of Object.keys(options.tables)) {
            this.tables.set(key, new Map())
        }
    }
}

