export const PERMS_DELIMITER = ",";
export const PERMS_SUBDELIMITER = ".";
export const PERMS_NEGATOR = "!";
export const PERMS_WILDCARD = "*";

type CoverType = "missing" | "denial";

// work from most generic to most precise
// This works in the positive direction
// negative permissions only exist to make large numbers of children perms easier to manage
// e.g. instead of adding view.document.1 view.document.2 view.document.4 etc you can instead to view.document !view.document.3
//
// Do not revoke a parent perm and then grant a child perm, this will not work

export class Perm {
	permPath: string[];
	isPositive: boolean;
	constructor(permPath: string[], isPositive: boolean = true) {
		this.permPath = permPath;
		this.isPositive = isPositive;
	}

	[Symbol.iterator]() {
		let index = -1;
		let data = this.permPath;

		return {
			next: () => ({ value: data[++index], done: !(index in data) })
		};
	}

	covers(permission: Perm | string): [false, CoverType] | [true] {
		const permToTest = typeof permission == "string" ? Perm.deserialise(permission) : (permission as Perm);
		if (!permToTest.isPositive) throw Error("Cannot perform cover check on a revoked permission");

		if (this.permPath.length > permToTest.permPath.length) return [false, "missing"]; // permToTest is less specific than me so I do not cover it

		for (let i = 0; i < Math.min(this.permPath.length, permToTest.permPath.length); i++) {
			if (this.permPath[i] != permToTest.permPath[i]) return [false, "missing"];
		}
		if (!this.isPositive) return [false, "denial"];
		return [true];
	}

	exactMatch(permission: Perm | string): boolean {
		const permToTest = typeof permission == "string" ? Perm.deserialise(permission) : (permission as Perm);

		if (this.permPath.length != permToTest.permPath.length) return false; // if perm lengths aren't the same then they definitely don't match exactly

		for (let i = 0; i < this.permPath.length; i++) {
			if (this.permPath[i] != permToTest.permPath[i]) return false;
		}

		return this.isPositive == permToTest.isPositive;
	}

	isChildOf(permission: Perm | string): boolean {
		const permToTest = typeof permission == "string" ? Perm.deserialise(permission) : (permission as Perm);

		if (permToTest.permPath.length > this.permPath.length) return false; // if permToTest is longer then it can never be a parent of this perm

		for (let i = 0; i < permToTest.permPath.length; i++) {
			if (this.permPath[i] != permToTest.permPath[i]) return false;
		}

		return true;
	}

	static serialise(perm: Perm): string {
		return `${perm.isPositive ? "" : PERMS_NEGATOR}${perm.permPath.join(PERMS_SUBDELIMITER)}`;
	}

	static deserialise(path: string): Perm {
		let isPositive = true;
		let pathWords = path.split(PERMS_SUBDELIMITER);
		if (pathWords[0].startsWith("!")) {
			pathWords[0] = pathWords[0].slice(1);
			isPositive = false;
		}
		if (pathWords[pathWords.length - 1] == PERMS_WILDCARD) {
			pathWords = pathWords.slice(0, -1);
		}
		return new Perm(pathWords, isPositive);
	}

	clone() {
		return new Perm(this.permPath, this.isPositive);
	}

	toString() {
		return Perm.serialise(this);
	}
}

export class PermsList {
	perms: Perm[];

	[Symbol.iterator]() {
		let index = -1;
		let data = this.perms;

		return {
			next: () => ({ value: data[++index], done: !(index in data) })
		};
	}

	constructor(perms?: Perm[]) {
		this.perms = perms || [];
	}

	has(perm: Perm | string): boolean {
		const deserialisedPerm = typeof perm == "string" ? Perm.deserialise(perm) : perm;
		let wasCoveredAtLeastOnce = false;
		for (const p of this.perms) {
			const result = p.covers(deserialisedPerm);
			if (result[0] == false && result[1] == "denial") return false; // if actively denied in perm then does not have
			if (result[0] == false && result[1] == "missing") continue; // if perm doesn't contain the word then not relevant but must continue as other perms may include it
			if (result[0] == true) wasCoveredAtLeastOnce = true; // if perm covers then mark as covered but keep checking in case of active denial
		}

		// if we get here then we have passed all perms without an active denial
		// if we covered the perm at least once then we pass
		// otherwise no relevant perm words were found and therefore we do not cover
		if (wasCoveredAtLeastOnce) return true;
		return false;
	}

	exactMatch(permission: Perm | string): boolean {
		const permToTest = typeof permission == "string" ? Perm.deserialise(permission) : (permission as Perm);

		for (const p of this.perms) {
			if (p.exactMatch(permToTest)) return true;
		}
		return false;
	}

	grant(permission: string | string[] | Perm | Perm[] | PermsList): void {
		let permsToAdd: Perm[];

		if (permission instanceof PermsList) permsToAdd = permission.perms;
		else if (typeof permission == "string") permsToAdd = [Perm.deserialise(permission)];
		else if (permission instanceof Perm) permsToAdd = [permission];
		else if (Array.isArray(permission) && permission.every((p) => typeof p == "string"))
			permsToAdd = permission.map((p) => Perm.deserialise(p));
		else permsToAdd = permission;

		for (const permToAdd of permsToAdd) {
			if (!permToAdd.isPositive) throw new Error("Cannot grant a negative permission");

			const negativePermToAdd = permToAdd.clone();
			negativePermToAdd.isPositive = false;
			if (this.exactMatch(negativePermToAdd)) this._remove(negativePermToAdd);

			if (this.has(permToAdd)) continue;

			for (const myPerm of this.perms) {
				// granting a more generic permission removes more precise perms from the list
				if (myPerm.isChildOf(permToAdd)) this._remove(myPerm);
			}

			this._add(permToAdd);
		}
	}

	revoke(permission: string | string[] | Perm | Perm[] | PermsList): void {
		let permsToRevoke: Perm[];

		if (permission instanceof PermsList) permsToRevoke = permission.perms;
		else if (typeof permission == "string") permsToRevoke = [Perm.deserialise(permission)];
		else if (permission instanceof Perm) permsToRevoke = [permission];
		else if (Array.isArray(permission) && permission.every((p) => typeof p == "string"))
			permsToRevoke = permission.map((p) => Perm.deserialise(p));
		else permsToRevoke = permission;

		for (const permToRevoke of permsToRevoke) {
			if (!permToRevoke.isPositive) throw new Error("Cannot revoke a negative permission");

			if (this.exactMatch(permToRevoke)) this._remove(permToRevoke);

			for (const myPerm of this.perms) {
				// Revoking a broad permission removes all granted child permissions
				if (myPerm.isChildOf(permToRevoke)) this._remove(myPerm);
			}

			const negativePermToRevoke = permToRevoke.clone();
			negativePermToRevoke.isPositive = false;
			if (this.exactMatch(negativePermToRevoke)) continue;

			if (this.has(permToRevoke)) this._add(negativePermToRevoke);
		}
	}

	clear() {
		this.perms = [];
	}

	_add(perm: Perm) {
		this.perms.push(perm);
	}

	_remove(perm: Perm) {
		this.perms = this.perms.filter((p) => !p.exactMatch(perm));
	}

	static serialise(permsList: PermsList) {
		return permsList.perms.map((p) => Perm.serialise(p)).join(PERMS_DELIMITER);
	}
	static deserialise(permsList: string[] | Perm[] | string): PermsList {
		if (typeof permsList == "string") {
			const perms = permsList.split(PERMS_DELIMITER).map((p) => Perm.deserialise(p));
			return new PermsList(perms);
		} else if (Array.isArray(permsList)) {
			if (permsList.every((p) => typeof p == "string")) {
				const perms = permsList.map((p) => Perm.deserialise(p));
				return new PermsList(perms);
			}
			return new PermsList(permsList);
		}
		throw Error("Cannot process data type");
	}

	toString() {
		return `PermsList{${PermsList.serialise(this)}}`;
	}
}
