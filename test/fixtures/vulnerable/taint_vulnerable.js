// Benchmark Corpus: Interprocedural Taint & Data Flow
const cp = require('child_process');

function handleRequest(req, res) {
  const untrustedDomain = req.query.domain;
  const commandToRun = "nslookup " + untrustedDomain;
  cp.exec(commandToRun);
}

function handleSafeRequest(req, res) {
  const untrustedAge = req.query.age;
  const cleanAge = parseInt(untrustedAge, 10);
  console.log("User age:", cleanAge);
}
