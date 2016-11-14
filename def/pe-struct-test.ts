/// <reference path="pe-struct.d.ts" />

import * as PE from "pe-struct";

const pe = PE.load(null);

console.log(pe.dosHeader);
console.log(pe.mdRoot);
console.log(pe.mdtMethodDef);

console.log(PE.hasMetadata(pe));
