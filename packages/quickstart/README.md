# @carchalabs/licensekit-quickstart

Try [LicenseKit](https://licensekit.carchalabs.com) from a terminal.

1. Get a trial key at [licensekit.carchalabs.com](https://licensekit.carchalabs.com/#try).
2. Activate this computer:

   ```
   npx @carchalabs/licensekit-quickstart activate LK-XXXX-XXXX-XXXX-XXXX
   ```

3. Turn off the network and check the license. It is verified offline from the signed lease:

   ```
   npx @carchalabs/licensekit-quickstart status
   ```

4. Release the seat:

   ```
   npx @carchalabs/licensekit-quickstart deactivate
   ```

The quickstart sends the license key, a hash of this computer's machine ID, the device name "LicenseKit quickstart" and the platform. It saves the lease without encryption in the per-user application data folder, because a terminal has no system keychain. See the [privacy notice](https://licensekit.carchalabs.com/privacy/).

Requires Node 22.13 or later. MIT License.
