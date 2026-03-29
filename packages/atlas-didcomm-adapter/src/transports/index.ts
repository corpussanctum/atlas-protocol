/**
 * Atlas DIDComm Adapter — Transport Implementations
 *
 * Each transport implements the DidcommTransport interface.
 * Import the specific transport you need:
 *
 *   import { CredoTransport } from '@corpussanctum/atlas-didcomm-adapter/transports/credo';
 */

export { CredoTransport } from "./credo.js";
export type { CredoAgentLike, CredoTransportOptions } from "./credo.js";
