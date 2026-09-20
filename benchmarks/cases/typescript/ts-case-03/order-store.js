export class OrderStore {
  constructor(orders) {
    this.orders = orders;
  }

  find(orderId, _requestingUser) {
    return this.orders.get(orderId);
  }
}
