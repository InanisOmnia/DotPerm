const { PermsList } = require("../dist");

const myPerms = PermsList.deserialise("test.test2,!test.test2.subtest");
console.log(myPerms.toString());
myPerms.grant("test.test2");
console.log(myPerms.toString());
myPerms.grant("document.4.view");
console.log(myPerms.toString());
myPerms.grant("document.4.edit");
console.log(myPerms.toString());
myPerms.grant("document.4");
console.log(myPerms.toString());
myPerms.grant("test.test2.subtest");
console.log(myPerms.toString());

console.log("---");

myPerms.revoke("document.4.edit");
console.log(myPerms.toString());
myPerms.revoke("document.4.edit");
console.log(myPerms.toString());
myPerms.revoke("test.test2.subtest.subsubtest");
console.log(myPerms.toString());
myPerms.revoke("test");
console.log(myPerms.toString());
myPerms.revoke("document");
console.log(myPerms.toString());
