#!/usr/bin/env node
import { run } from './cli';

run(process.argv.slice(2), { out: (line) => console.log(line) }).then(
  (code) => {
    process.exitCode = code;
  },
  (error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  },
);
