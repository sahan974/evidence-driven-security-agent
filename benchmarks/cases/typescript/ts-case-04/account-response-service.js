import { AccountPresenter } from "./account-presenter.js";

export class AccountResponseService {
  constructor(presenter = new AccountPresenter()) {
    this.presenter = presenter;
  }

  render(account) {
    if (!account?.id) throw new Error("an account id is required");
    return this.presenter.serialize(account);
  }
}
