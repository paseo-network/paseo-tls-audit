/**
 * Report generator.
 *
 * Reads the audit data from stdin (output of check-tls.ts) and the HTML
 * template, injects the data, and writes the final report to stdout.
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const TEMPLATE = resolve(ROOT, "template", "report.html");
const DATA_FILE = resolve(ROOT, "output", "report_data.json");

const template = readFileSync(TEMPLATE, "utf-8");
const data = readFileSync(DATA_FILE, "utf-8").trim();

const today = new Date().toISOString().slice(0, 10);

const html = template
  .replace("__REPORT_DATA__", data)
  .replace(/__REPORT_DATE__/g, today);

process.stdout.write(html);
