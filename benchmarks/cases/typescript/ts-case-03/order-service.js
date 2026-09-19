import { OrderStore } from "./order-store.js";

export class OrderService {
  retrieve(orders, request) {
    const orderId = request.orderId.trim();
    if (!orderId) throw new Error("an order id is required");
    return new OrderStore(orders).find(orderId, request.requestingUser);
  }
}
