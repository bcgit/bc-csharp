using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Tests
{
    /// <summary>
    /// OID coverage for the Extended Key Usage KeyPurposeID constants, guarding their branch numbers against typos
    /// and checking that they round-trip through GetInstance.
    /// </summary>
    [TestFixture]
    public class KeyPurposeIDTest
    {
        private static readonly Dictionary<KeyPurposeID, string> KeyPurposeIDMap =
            new Dictionary<KeyPurposeID, string>()
        {
            { KeyPurposeID.id_kp_documentSigning, "1.3.6.1.5.5.7.3.36" },           // RFC 9336
            { KeyPurposeID.id_kp_jwt, "1.3.6.1.5.5.7.3.37" },                       // RFC 9509
            { KeyPurposeID.id_kp_httpContentEncrypt, "1.3.6.1.5.5.7.3.38" },        // RFC 9509
            { KeyPurposeID.id_kp_oauthAccessTokenSigning, "1.3.6.1.5.5.7.3.39" },   // RFC 9509
            { KeyPurposeID.id_kp_imUri, "1.3.6.1.5.5.7.3.40" },                     // RFC 9734
            { KeyPurposeID.id_kp_configSigning, "1.3.6.1.5.5.7.3.41" },             // RFC 9809
            { KeyPurposeID.id_kp_trustAnchorConfigSigning, "1.3.6.1.5.5.7.3.42" },  // RFC 9809
            { KeyPurposeID.id_kp_updatePackageSigning, "1.3.6.1.5.5.7.3.43" },      // RFC 9809
            { KeyPurposeID.id_kp_safetyCommunication, "1.3.6.1.5.5.7.3.44" },       // RFC 9809
            { KeyPurposeID.id_kp_secureShellClient, "1.3.6.1.5.5.7.3.21" },         // RFC 6187
            { KeyPurposeID.id_kp_secureShellServer, "1.3.6.1.5.5.7.3.22" },         // RFC 6187
            { KeyPurposeID.id_kp_cmcArchive, "1.3.6.1.5.5.7.3.29" },                // RFC 6402
            { KeyPurposeID.id_kp_bundleSecurity, "1.3.6.1.5.5.7.3.35" },            // RFC 9174
            // Kerberos PKINIT, id-pkinit arc rather than id-kp
            { KeyPurposeID.id_kp_pkinitClientAuth, "1.3.6.1.5.2.3.4" },             // RFC 4556
            { KeyPurposeID.id_kp_pkinitKdc, "1.3.6.1.5.2.3.5" },                    // RFC 4556
        };
        private static readonly IEnumerable<DerObjectIdentifier> KeyPurposeIDs = KeyPurposeIDMap.Keys;

        [TestCaseSource(nameof(KeyPurposeIDs))]
        public void CheckKeyPurposeID(KeyPurposeID keyPurposeID)
        {
            var expectedID = KeyPurposeIDMap[keyPurposeID];
            Assert.AreEqual(expectedID, keyPurposeID.GetID(), $"wrong ID for KeyPurposeID: {expectedID}");

            // NOTE: Round-trip to DerObjectIdentifier because we are trying to remove subclassing KeyPurposeID
            DerObjectIdentifier recoveredOid = DerObjectIdentifier.GetInstance(keyPurposeID.GetEncoded());
            Assert.AreEqual(expectedID, recoveredOid.GetID(), $"KeyPurposeID did not round-trip: {expectedID}");
        }
    }
}
