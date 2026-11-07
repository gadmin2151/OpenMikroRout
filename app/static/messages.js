import { messagesA } from "./messages-a.js";
import { messagesB } from "./messages-b.js";
import { messagesExtra } from "./messages-extra.js";

/** Canonical UI source -> [Russian, English]. Network identifiers stay unchanged. */
export const messages = { ...messagesA, ...messagesB, ...messagesExtra };
