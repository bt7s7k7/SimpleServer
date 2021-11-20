import { expect } from "chai"
import { SimpleDB } from "../../src/simpleDB/SimpleDB"
import { Struct } from "../../src/struct/Struct"
import { Type } from "../../src/struct/Type"
import { describeMember } from "../testUtil/describeMember"

class Foo extends Struct.define("Foo", {
    id: Type.string,
    name: Type.string
}) { }


function create() {
    return new SimpleDB({
        tables: {
            foo: Foo
        }
    })
}

describeMember(() => SimpleDB, () => {
    it("Should be creatable", () => {
        create()
    })

    it("Should be able to put and get a value", () => {
        const inst = create()

        inst.put("foo", new Foo({ id: "0", name: "boo" }))
        expect(inst.get("foo", "0")).to.have.property("name", "boo")
    })

    it("Should return null on missing entity", () => {
        const inst = create()

        expect(inst.tryGet("foo", "0")).to.be.null
    })

    it("Should throw on missing entity", () => {
        const inst = create()

        expect(() => inst.get("foo", "0")).to.throw("with id \"0\"")
    })

    it("Should be able to export state", () => {
        const inst = create()

        inst.put("foo", new Foo({ id: "0", name: "boo" }))
        expect(inst.export()).to.deep.equal({
            tables: {
                foo: {
                    "0": {
                        id: "0",
                        name: "boo"
                    }
                }
            }
        })
    })

    it("Should be able to import state", () => {
        const inst = create()

        inst.import({
            tables: {
                foo: {
                    "0": {
                        id: "0",
                        name: "boo"
                    }
                }
            }
        })

        expect(inst.get("foo", "0")).to.have.property("name", "boo")
        expect(inst.get("foo", "0")).to.have.property("serialize")
    })
})