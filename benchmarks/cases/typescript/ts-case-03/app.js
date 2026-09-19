import { OrderService } from "./order-service.js";

class OrderRequest {
  constructor(orderId, requestingUser) {
    this.orderId = orderId;
    this.requestingUser = requestingUser;
  }
}

class OrderEndpoint {
  constructor(service = new OrderService()) {
    this.service = service;
  }

  get(orders, request) {
    return this.service.retrieve(orders, request);
  }
}

export function loadOrder(orders, orderId, requestingUser) {
  return new OrderEndpoint().get(orders, new OrderRequest(orderId, requestingUser));
}
