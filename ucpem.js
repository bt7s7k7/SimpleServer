/// <reference path="./.vscode/config.d.ts" />

const { project, github } = require("ucpem")

project.prefix("src").res("simpleDB",
    github("bt7s7k7/Struct").res("struct")
)

project.prefix("src").res("simpleAuth",
    project.ref("simpleDB"),
    github("bt7s7k7/Struct").res("structSync")
)

project.prefix("test").use(github("bt7s7k7/TestUtil").res("testUtil"))