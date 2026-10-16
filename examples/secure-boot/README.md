# Signed OTA updates

Two versions of the [wifi-template](../wifi-template) application whose devices only install
firmware signed with a key they trust. Both use ESP-IDF's *Require signed app images* with Secure
Boot V2 signatures, and by default neither burns eFuses, so a board can always be erased and reused.
Hardware secure boot is a separate, deliberate step, described in self-signed.

| Example | Who signs the firmware | Status |
|---|---|---|
| [self-signed](self-signed/wifi-template) | You, with your own key | Ready to use |
| [bluecherry-signed](bluecherry-signed/wifi-template) | BlueCherry, after checking that the upload is yours | Concept, work in progress |

Start with self-signed. It also explains how the fingerprint BlueCherry records for a signed image
is found, and what hardware secure boot would add.
