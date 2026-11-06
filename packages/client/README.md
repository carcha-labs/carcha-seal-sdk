# Client scenarios

`tests/vectors.json` records how the reference SDK (`@carchalabs/seal-electron`) behaves as a license client: scenarios of activation, check-ins, offline grace, clock checks, refusals, deactivation, offline files and feature decryption, each run with a scripted license server and a set clock. For every step it holds what the SDK sent (path and body) and what it returned (the license state or the error code and message). The SDK version and platform in request bodies are placeholders.

The native client used by the C++, C# and Java SDKs must give the same requests and results for every scenario.

```
npm run build                                  # from the repository root
node packages/client/tests/make-vectors.js     # regenerate after a deliberate change to the SDK's behaviour
npm test -w packages/sdk-electron              # client-vectors.test.ts: the file still matches the SDK
```

Leases are signed with the throwaway test key of `../lease/tests/vectors.json`.
