'use strict';

class DotPerm {
    constructor(perms) {
        this.perms = perms || [];
    }

    has(perm) {
        // if there are no perms in this structure then they dont have the perm so false
        if (!this.perms || !this.perms.length) { return false; }
        // get the current perms to allow mutation
        let currentPerms = [...this.perms];

        // get all sections of requested perm as array
        let splitPerms = perm.split(".");

        // assume check has passed unless otherwise
        let checkPassed = true;

        // store perms in a separate array to allow mutation
        let relevantPerms = [...currentPerms];
        // store offset of removed perms so that elts aren't remove from the wrong index
        let relevantPermsOffset = 0;

        // loop over all the perms the obj has
        for (let cpi = 0; cpi < currentPerms.length; cpi++) {
            // get the current perm
            let currentPerm = currentPerms[cpi];

            // remove irrelevant main bodies (if a.b... is requested then a.c is irrelevant)
            for (let rpi = 0; rpi < splitPerms.length; rpi++) {
                let currentRequestedPermEt = splitPerms[rpi];
                let currentPermElt = currentPerm[rpi + 1]; // +1 so it ignores the flags column

                // a is equivalent to a.*, include this and break the loop as there is no more to come
                if (!currentPermElt) {
                    break
                }
                // * matches all children, include this and break the loop as there is no more to come
                if (currentPermElt == "*") {
                    break
                }
                // a matches a then include this and continue the loop as the structure moves deeper
                if (currentPermElt == currentRequestedPermEt) {
                    continue
                }

                // has matched nothing previously therefore remove it from the included list
                relevantPerms.splice(cpi + relevantPermsOffset, 1);
                // back step once so that removing an element from the relevant array isn't wrong by the number of elements already removed
                relevantPermsOffset--;
                break;
            }
        }

        // if length of perm chain is longer than the requested perm chain it must be a child and therefore irrelevant
        relevantPerms = relevantPerms.filter((elt) => {
            // -1 for flags index
            if (elt.length - 1 > splitPerms.length) {
                return false
            }
            return true
        });


        // if there are no perms left after all relevant perms are removed then must not have permission
        if (relevantPerms.length == 0) {
            checkPassed = false;
            return checkPassed
        }

        // find index if there is a perm that contains the not ! tag
        let index = relevantPerms.findIndex((elt) => {
            return elt[0].includes("!")
        });
        // if an elt with that tag exists
        if (index >= 0) {
            checkPassed = false
        }

        // if got all the way here without failing a perm check then all perms passed
        // return the result
        return checkPassed;
    }

    give(perm) {
        this.perms.push(...this.constructor.deserialize(perm));
        return perm;
    }

    revoke(perm) {
        const deperm = this.constructor.deserialize(perm)[0];
        const idx = this.perms.findIndex((elt) => {
            for (let i = 0; i < elt.length; i++) {
                if(elt[i] != deperm[i]) {
                    return false
                }            
            }
            return true;
        });
        if (idx == -1) {
            return null
        }
        this.perms.splice(idx, 1);
        return perm;
    }

    get permsList() {
        return this.perms ? this.perms.map((perm) => {
            return [perm[0] || "", perm.slice(1).join(".")]
        }) : null;
    }

    static deserialize(perms) {
        if (!perms) { return null }
        perms = perms.split(",")
        perms = perms.map((perm) => {
            if (perm.includes("-")) {
                perm = perm.split("-")
                perm = [...perm[0], ...perm[1].split(".")]
            } else {
                perm = ["", ...perm.split(".")]
            }
            return perm;
        });
        return perms
    }

    static serialize(perms) {
        if (!perms) {
            return null
        }
        let outPerms = perms.map((perm) => {
            return [...perm[0], perm.slice(1).join(".")].join("-")
        }).join(",")
        return outPerms;
    }
}

module.exports = DotPerm;