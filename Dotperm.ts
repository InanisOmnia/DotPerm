export const PERMS_DELIMITER = ",";
export const PERMS_SUBDELIMITER = ".";
export const PERMS_NEGATOR = "!";
export const PERMS_WILDCARD = "*";

type CoverType = "missing" | "denial";

export class Perm {
	permPath: string[];
	isPositive: boolean;
	constructor(permPath: string[], isPositive: boolean = true) {
		this.permPath = permPath;
		this.isPositive = isPositive;
	}

	covers(permission: Perm): [false, CoverType] | [true];
	covers(permission: string): [false, CoverType] | [true];
	covers(permission: unknown): [false, CoverType] | [true] {
		const permToTest = typeof permission == "string" ? Perm.deserialise(permission) : (permission as Perm);
		if (!permToTest.isPositive) throw Error("Cannot perform cover check on a revoked permission");

		if (this.permPath.length > permToTest.permPath.length) return [false, "missing"]; // permToTest is less specific than me so I do not cover it

		for (let i = 0; i < Math.min(this.permPath.length, permToTest.permPath.length); i++) {
			if (this.permPath[i] != permToTest.permPath[i]) return [false, "missing"];
		}
		if (!this.isPositive) return [false, "denial"];
		return [true];
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

	toString() {
		return Perm.serialise(this);
	}
}

export class PermsList {
	perms: Perm[];

	constructor(perms?: Perm[]) {
		this.perms = perms || [];
	}

	has(perm: string): boolean;
	has(perm: Perm): boolean;
	//
	has(perm: unknown): boolean {
		const deserialisedPerm = typeof perm == "string" ? Perm.deserialise(perm) : (perm as Perm);
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

	give(permission: string): void;
	give(permission: string[]): void;
	give(...permission: string[]): void;
	give(permission: Perm): void;
	give(...permission: Perm[]): void;
	give(permission: Perm[]): void;
	give(permission: PermsList): void;
	//
	give(permission: unknown): void {
		let permsToAdd: Perm[];

		if (permission instanceof PermsList) permsToAdd = permission.perms;
		else if (Array.isArray(permission) && permission[0] instanceof Perm) permsToAdd = permission;
		else if (Array.isArray(permission) && typeof permission[0] == "string")
			permsToAdd = permission.map((p) => Perm.deserialise(p));
		else if (typeof permission == "string") permsToAdd = [Perm.deserialise(permission)];
		else if (permission instanceof Perm) permsToAdd = [permission];

		throw Error("Method not yet implemented");
		// for (const perm of permsToAdd) {
		// 	// !
		// }
	}

	revoke(permission: string): void;
	revoke(permission: string[]): void;
	revoke(...permission: string[]): void;
	revoke(permission: Perm): void;
	revoke(...permission: Perm[]): void;
	revoke(permission: Perm[]): void;
	revoke(permission: PermsList): void;
	//
	revoke(permission: unknown): void {
		let permsToRevoke: Perm[];

		if (permission instanceof PermsList) permsToRevoke = permission.perms;
		else if (Array.isArray(permission) && permission[0] instanceof Perm) permsToRevoke = permission;
		else if (Array.isArray(permission) && typeof permission[0] == "string")
			permsToRevoke = permission.map((p) => Perm.deserialise(p));
		else if (typeof permission == "string") permsToRevoke = [Perm.deserialise(permission)];
		else if (permission instanceof Perm) permsToRevoke = [permission];

		throw Error("Method not yet implemented");
		// for (const perm of permsToRevoke) {
		// 	// !
		// }
	}

	static serialise(permsList: PermsList) {
		return permsList.perms.map((p) => Perm.serialise(p)).join(PERMS_DELIMITER);
	}

	static deserialise(...permsList: string[]): PermsList;
	static deserialise(...permsList: Perm[]): PermsList;
	static deserialise(permsList: string[]): PermsList;
	static deserialise(permsList: Perm[]): PermsList;
	//
	static deserialise(permsList: unknown): PermsList {
		if (Array.isArray(permsList)) {
			if (permsList[0] instanceof Perm) return new PermsList(permsList);
			const perms = permsList.map((p) => Perm.deserialise(p));
			return new PermsList(perms);
		} else if (typeof permsList == "string") {
			const perms = permsList.split(PERMS_DELIMITER).map((p) => Perm.deserialise(p));
			return new PermsList(perms);
		}
		throw Error("Cannot process data type");
	}

	toString() {
		return PermsList.serialise(this);
	}
}

const myPerms = PermsList.deserialise("test.test2,!test.test2.subtest");
console.log(myPerms.toString());
console.log(myPerms.has("test"));
console.log(myPerms.has("test.test2"));
console.log(myPerms.has("test.test3"));
console.log(myPerms.has("test.test2.subtestyes"));
console.log(myPerms.has("test.test2.subtest"));
console.log(myPerms.has("test.test2.subtest.subsubtest"));
console.log("-----");
