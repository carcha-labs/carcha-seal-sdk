# Carcha Seal and your users' privacy

For software vendors who build Carcha Seal into their apps: what the SDK reads on your users' computers, what it
sends to the licence server and what it keeps on the device, so that you can describe it in your own privacy
notice. This is Carcha Labs' reading of the GDPR and the ePrivacy Directive, not legal advice. The facts below are
read from the code in this repository (`packages/sdk-electron`, `packages/core`, `packages/hwid`).

## Who is responsible for what

- **You are the controller** of your users' licensing data: you decide to license your app and which licence
  checks it makes.
- **On the hosted server (`seal.carchalabs.com`), Carcha Labs is your processor.** It stores and uses the data only
  to run licensing for you.
- **On a server you run yourself**, Carcha Labs receives none of this data.

## What is sent to the licence server

The SDK sends a request when the app activates (`activate`), checks the licence while online (`check`) and
deactivates (`deactivate`). An offline request file (`offlineRequest`) holds the same fields as an activation.

| Data | What it is | Sent with |
|---|---|---|
| Licence key | The key your customer entered. The hosted server stores only a hash of it. | Every request |
| Product code | The `product` option you set | Every request |
| Device fingerprint | SHA-256 of `licensekit:<product>:<OS machine id>`. The OS machine id is the IOPlatformUUID on macOS, the MachineGuid on Windows and `/etc/machine-id` on Linux. The raw id is not sent. | Every request |
| Hardware component hashes | One HMAC-SHA256 per component, made on the device and keyed with `licensekit:<product>`: system UUID, motherboard or system serial, internal disk serials, factory network (MAC) addresses, OS install id, CPU model and GPU model, whichever the computer reports; at most 32. Raw serials and addresses are not sent. Only when `@carchalabs/seal-hwid` is installed and the `hardware` option is not `false`. | Every request |
| Virtual machine flag | Whether the app runs in a virtual machine | With the component hashes |
| Device public key | An X25519 public key derived on the device from its hardware, used to encrypt feature keys for that device. The hosted server does not store it. | Activation and check-in, with `@carchalabs/seal-hwid` 0.2 or later |
| Machine name | The second argument of `activate()` and `offlineRequest()`. **If you leave it out, the SDK sends the computer's host name** (first 80 characters), which often contains the user's name, such as "Jane's MacBook Pro". | Activation |
| Platform | `darwin`, `win32` or `linux` | Activation |
| App and SDK version | The `appVersion` option and the SDK's own version | Activation and check-in |
| IP address | Part of every network request | Every request |

On the hosted server:

- The licence record holds what you or your payment connection gave it (the customer's name and email).
- Each device record holds the fingerprint, component hashes, machine name, platform, versions, VM flag, and the
  activation and last check-in times.
- The events log records device events with the machine name.
- IP addresses are not stored in the database. They are counted in memory for rate limits for at most one hour,
  they appear in the web server's access logs, which are deleted after 15 days, and Cloudflare handles all
  traffic.
- All of it is kept while your account exists. Releasing a device or revoking a licence marks the record but does
  not delete it. When your account is deleted, all of it is deleted with it, and the server's backups keep it
  until they rotate out (14 backups).
- Carcha Labs' own privacy notice, for its vendor accounts and website, is at
  [seal.carchalabs.com/privacy](https://seal.carchalabs.com/privacy/).

## What is kept on the device

`license.dat` in the `storageDir` you choose, readable only by the user's account (file mode 0600). It holds:

- **The licence key.** It is in plain text unless you pass a `secureStore`, such as Electron's `safeStorage`.
- **The signed lease.** The lease is signed but not encrypted, so anyone with the file can read it. It contains the
  device fingerprint, the features, the expiry dates and the licence holder's name, if the licence has one.
- The time of the last successful check-in, the last refusal and the notices from the server.

`deactivate()` deletes the file.

## Is this personal data

Yes, when it relates to a person, which it usually does for an app on someone's own computer.

- **The hashes are pseudonymised, not anonymous.** The key is the product code, and the product code is not
  secret: it is in your app. Anyone who has a hash and the product code can test candidate values. This is
  practical for small value spaces such as a MAC address, whose first half names the maker. The GDPR treats
  pseudonymised data as personal data (Recital 26).
- **The hashes are the same for all apps with the same product code.** The hosted server makes product codes unique
  within one vendor account, not across accounts, so two vendors who choose the same code get the same hashes
  for the same computer. Choose a product code no one else is likely to use, such as one with your company name in
  it.
- The machine name, the licence holder's name and the IP address are personal data in their own right.

## Consent for reading the device (ePrivacy Article 5(3))

Article 5(3) of the ePrivacy Directive (2002/58/EC) covers storing information on, and gaining access to
information already stored on, a user's device. It applies whether or not the information is personal data. The
EDPB's Guidelines 2/2023 on its technical scope (version 2.0, October 2024) read it as covering:

- software such as an SDK that makes the device send information (paragraphs 33 and 34);
- reading device properties to build a fingerprint (paragraph 43);
- identifiers derived on the device, including hashed ones, once they are sent (paragraphs 61 to 63).

The Guidelines do not count reading the device for processing that stays on the device as gaining access
(paragraph 44). Storing `license.dat` is storage on the device, which the Article covers as well.

The Article requires the user's consent unless the storage or access is "strictly necessary in order for the
provider of an information society service explicitly requested by the subscriber or user to provide the service".
Whether a licence check is strictly necessary for the app your user installed is your assessment as the
controller, and the Guidelines do not address the exemptions (paragraph 4). National laws that implement the
Directive apply too. Two things make the case easier to argue:

- The SDK reads the device only to tell one computer from another for the licence's seat limit.
- It sends nothing for analytics or advertising.

## What you can change

- **Machine name.** Pass your own label as the second argument of `activate()` and `offlineRequest()`, for
  example one the user types or a fixed one such as "Desktop". The host name is then not sent. Your console
  shows the label to tell a licence's devices apart.
- **Hardware components.** Set `hardware: false` to send none of them. Two things then stop: a device no longer
  keeps its seat after a new disk, network card or OS install, and feature keys are no longer bound to the
  device's hardware.
- **Licence key at rest.** Pass a `secureStore` to encrypt `license.dat` with the operating system's key store.
- **Fallback fingerprint.** `allowFallbackFingerprint` is off by default. When it is on and the OS machine id cannot
  be read, the fingerprint is made from the host name, CPU model and MAC addresses. They are hashed before they
  are sent.

## Wording for your privacy notice

Adapt this to what your app does, then have it checked for your jurisdiction. For the retention period: on the
hosted server the records stay until your account is deleted.

> **Licence activation.** To check your licence, [App] uses Carcha Seal, a licensing service provided by Carcha
> Labs, which processes the data on our behalf. When you activate [App] and when it checks your licence, it sends
> to the licence server: your licence key; a code derived from your computer's system identifier; codes derived
> from hardware identifiers such as serial numbers and network addresses (the identifiers themselves are not
> sent); whether [App] runs in a virtual machine; [the name of your computer;] your operating system and the versions
> of [App]; and, as with any network connection, your IP address. We use this to make sure the licence is used on
> no more computers than it allows, and to let [App] work offline between checks. We keep it [for how long].
> [App] stores your licence key and a signed licence file on your computer.
