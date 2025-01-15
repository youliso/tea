import test from "ava";
import { teaDecrypt, teaEncrypt } from "../index.js";

const s_v = "5LaL7ZF3dQhvcmxkIQ==";
const v = "Hello, World!";
const k = Buffer.from("c2VjcmV0IGtleQ==");

test("teaDecrypt", (t) => {
  t.is(
    teaDecrypt(Buffer.from(s_v, "base64"), k, 16).toString(),
    "Hello, World!"
  );
});

test("teaEncrypt", (t) => {
  t.is(teaEncrypt(Buffer.from(v), k, 16).toString("base64"), s_v);
});
