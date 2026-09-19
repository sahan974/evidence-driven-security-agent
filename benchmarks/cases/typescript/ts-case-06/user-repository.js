export class UserRepository {
  constructor(database) {
    this.database = database;
  }

  findByEmail(email) {
    return this.database.query(`SELECT id FROM users WHERE email = '${email}'`);
  }
}
