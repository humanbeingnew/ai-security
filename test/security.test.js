import test from "node:test";
import assert from "node:assert/strict";
import { analyze, campaignId } from "../src/engine.js";

test("detects SQL injection",()=>{const x=analyze({url:"https://x.test/?q=' OR 1=1",headers:{"user-agent":"Mozilla"}});assert.equal(x.action,"BLOCK");assert.ok(x.hits.some(h=>h.type==="SQL Injection"));});
test("detects XSS",()=>{const x=analyze({url:"https://x.test/?q=<script>alert(1)</script>",headers:{"user-agent":"Mozilla"}});assert.equal(x.action,"BLOCK");});
test("detects traversal",()=>{const x=analyze({url:"https://x.test/../../etc/passwd",headers:{"user-agent":"Mozilla"}});assert.equal(x.action,"BLOCK");});
test("normal request allowed",()=>{const x=analyze({url:"https://x.test/products?id=123",headers:{"user-agent":"Mozilla"}});assert.equal(x.action,"ALLOW");});
test("campaign ids are stable",()=>{const a=campaignId({ip:"1.2.3.4",path:"/login",hits:[{type:"XSS"}]});const b=campaignId({ip:"1.2.3.4",path:"/login?x=1",hits:[{type:"XSS"}]});assert.equal(a,b);});
