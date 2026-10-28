# Security and private data

The identity file contains a fixed PIN and device seed. The authentication store contains pairing material. Keep both in private persistent directories and preserve them across upgrades. Use `tools/identity.py show-pin` only when you intend to display the PIN locally.

The media socket carries phone content and accepts input commands. Place it in a directory with mode `0700` and run the receiver and consumer under the same trusted UID. The recording example writes private files; remove captures when they are no longer needed.

Do not attach identities, pairing stores, unredacted packet captures or private media to issues, pull requests or CI artifacts. Ordinary bug reports should contain versions, the failure stage and a sanitized event timeline.

For authentication bypass, key disclosure or code-execution issues, use GitHub private vulnerability reporting if enabled. Otherwise request a private contact through an issue without including exploit details or private material.
