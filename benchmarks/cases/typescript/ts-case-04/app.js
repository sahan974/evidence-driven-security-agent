import { AccountResponseService } from "./account-response-service.js";

class AccountResponseEndpoint {
  constructor(service = new AccountResponseService()) {
    this.service = service;
  }

  get(account) {
    return this.service.render(account);
  }
}

export function accountResponse(account) {
  return new AccountResponseEndpoint().get(account);
}
