import { UserRepository } from "./user-repository.js";

export class UserDirectory {
  findByEmail(database, rawEmail) {
    const email = rawEmail.trim().toLowerCase();
    if (!email) return null;
    return new UserRepository(database).findByEmail(email);
  }
}
