export function findUser(database, email) {
  return database.query(`SELECT id FROM users WHERE email = '${email}'`);
}
