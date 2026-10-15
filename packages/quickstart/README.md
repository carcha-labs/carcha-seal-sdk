# @carchalabs/seal-quickstart

Try [Carcha Seal](https://seal.carchalabs.com) (formerly LicenseKit) from a terminal.

1. Get a trial key at [seal.carchalabs.com](https://seal.carchalabs.com/#try).
2. Activate this computer:

   ```
   npx @carchalabs/seal-quickstart activate LK-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
   ```

3. Turn off the network and check the license. It is verified offline from the signed lease:

   ```
   npx @carchalabs/seal-quickstart status
   ```

4. Release the seat:

   ```
   npx @carchalabs/seal-quickstart deactivate
   ```

The quickstart sends the license key, a hash of this computer's machine ID, the device name "Carcha Seal quickstart" and the platform. It saves the lease without encryption in the per-user application data folder, because a terminal has no system keychain. See the [privacy notice](https://seal.carchalabs.com/privacy/).

Requires Node 22.13 or later. MIT License.
