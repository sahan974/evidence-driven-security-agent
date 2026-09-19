import { UserDirectory } from "./user-directory.js";

class UserSearchEndpoint {
  constructor(directory = new UserDirectory()) {
    this.directory = directory;
  }

  search(database, email) {
    return this.directory.findByEmail(database, email);
  }
}

export function findUser(database, email) {
  return new UserSearchEndpoint().search(database, email);
}
