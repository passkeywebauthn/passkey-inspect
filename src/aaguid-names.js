// A curated map of well-known AAGUIDs to human-readable authenticator names.
//
// AAGUIDs identify an authenticator *model* (not an individual key). This list
// is a deliberately small, high-confidence subset — the passkey providers and
// security keys developers see most often — drawn from vendor documentation and
// the FIDO Metadata Service. It is NOT exhaustive: an unknown AAGUID is not
// suspicious, and for authoritative model data you should consult the FIDO MDS.
// Contributions that add or correct entries are welcome.

export const AAGUID_NAMES = {
  // Synced passkey providers (platform / password managers)
  "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
  "adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
  "fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "Apple iCloud Keychain",
  "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello (hardware)",
  "9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello (VBS hardware)",
  "6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello (software)",
  "bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
  "d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
  "531126d6-e717-415c-9320-3d9aa6981239": "Dashlane",
  "b84e4048-15dc-4dd0-8640-f4f60813c8af": "NordPass",
  "0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6": "Proton Pass",

  // Roaming hardware security keys
  "f8a011f3-8c0a-4d15-8006-17111f9edc7d": "Security Key by Yubico",
  "ee882879-721c-4913-9775-3dfcce97072a": "YubiKey 5 Series",
  "fa2b99dc-9e39-4257-8f92-4a30d23c4118": "YubiKey 5 Series (NFC)",
  "d8522d9f-575b-4866-88a9-ba99fa02f35b": "YubiKey Bio Series",
  "cb69481e-8ff7-4039-93ec-0a2729a154a8": "YubiKey 5 Series (FW5.1)",
};

/** Look up a formatted AAGUID UUID string; returns a model name or null. */
export function lookupAaguid(uuid) {
  if (typeof uuid !== "string") return null;
  return AAGUID_NAMES[uuid.toLowerCase()] ?? null;
}
