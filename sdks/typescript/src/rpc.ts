// Promise and async-iterator forms of grpc-js's callback and stream calls. They reject
// with grpc-js's own ServiceError; the cell and control clients map that to typed errors.
import { once } from "node:events";
import * as grpc from "@grpc/grpc-js";

/** What a client needs of a method: its path and how to encode requests and decode responses. */
export interface ClientMethod<Req, Res> {
  path: string;
  requestSerialize: (value: Req) => Buffer;
  responseDeserialize: (bytes: Buffer) => Res;
}

function settle<Res>(resolve: (value: Res) => void, reject: (reason: unknown) => void): grpc.requestCallback<Res> {
  return (error, value) => {
    if (error) reject(error);
    else if (value === undefined) reject(new Error("call ended without a response"));
    else resolve(value);
  };
}

/** One request, one response. */
export function unary<Req, Res>(
  client: grpc.Client,
  method: ClientMethod<Req, Res>,
  request: Req,
  options: grpc.CallOptions = {},
): Promise<Res> {
  return new Promise((resolve, reject) => {
    client.makeUnaryRequest(
      method.path,
      method.requestSerialize,
      method.responseDeserialize,
      request,
      new grpc.Metadata(),
      options,
      settle(resolve, reject),
    );
  });
}

/**
 * Streams `requests`, then waits for the single response. If `requests` itself throws (a
 * file read fails, say), the call is cancelled and the promise rejects with that error.
 */
export function clientStream<Req, Res>(
  client: grpc.Client,
  method: ClientMethod<Req, Res>,
  requests: Iterable<Req> | AsyncIterable<Req>,
  options: grpc.CallOptions = {},
): Promise<Res> {
  return new Promise((resolve, reject) => {
    let failed: { error: unknown } | undefined;
    const done = settle(resolve, reject);
    const call = client.makeClientStreamRequest(
      method.path,
      method.requestSerialize,
      method.responseDeserialize,
      new grpc.Metadata(),
      options,
      (error, value) => (failed === undefined ? done(error, value) : reject(failed.error)),
    );
    void writeAll(call, requests, (error) => {
      failed = { error };
    });
  });
}

/** One request, then the responses as they arrive. */
export async function* serverStream<Req, Res>(
  client: grpc.Client,
  method: ClientMethod<Req, Res>,
  request: Req,
  options: grpc.CallOptions = {},
): AsyncGenerator<Res> {
  const call = client.makeServerStreamRequest(
    method.path,
    method.requestSerialize,
    method.responseDeserialize,
    request,
    new grpc.Metadata(),
    options,
  );
  // grpc-js streams iterate as `any`; the method's deserializer produced each message.
  yield* call as AsyncIterable<Res>;
}

/** Streams `requests` while yielding the responses as they arrive. */
export async function* bidiStream<Req, Res>(
  client: grpc.Client,
  method: ClientMethod<Req, Res>,
  requests: Iterable<Req>,
  options: grpc.CallOptions = {},
): AsyncGenerator<Res> {
  const call = client.makeBidiStreamRequest(
    method.path,
    method.requestSerialize,
    method.responseDeserialize,
    new grpc.Metadata(),
    options,
  );
  let failed: { error: unknown } | undefined;
  const sending = writeAll(call, requests, (error) => {
    failed = { error };
  });
  try {
    yield* call as AsyncIterable<Res>;
  } catch (error) {
    throw failed === undefined ? error : failed.error;
  }
  await sending;
  if (failed !== undefined) throw failed.error;
}

/**
 * Writes `requests` in order, pulling the next only once the last was taken (waiting for
 * `drain` when grpc-js's buffer is full), then half-closes. Stops when the call ends.
 * Never rejects: a failed call's status reaches the caller through the response side, and
 * if `requests` itself throws, `onSourceError` gets the error and the call is cancelled.
 */
async function writeAll<Req>(
  call: grpc.ClientWritableStream<Req>,
  requests: Iterable<Req> | AsyncIterable<Req>,
  onSourceError: (error: unknown) => void,
): Promise<void> {
  const ended = new AbortController();
  call.once("status", () => ended.abort());
  try {
    for await (const request of requests) {
      if (ended.signal.aborted) return;
      // A rejection means the call ended or failed while waiting; its status says why.
      if (!call.write(request)) await once(call, "drain", { signal: ended.signal }).catch(() => ended.abort());
    }
  } catch (error) {
    onSourceError(error);
    call.cancel();
    return;
  }
  if (!ended.signal.aborted) call.end();
}
