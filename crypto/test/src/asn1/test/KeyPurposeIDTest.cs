using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Asn1.Tests
{
    /**
     * OID coverage for the recently-added Extended Key Usage KeyPurposeId constants (RFC 9336, RFC 9734
     * and RFC 9809), guarding their id-kp branch numbers against typos. All live under the PKIX id-kp
     * arc 1.3.6.1.5.5.7.3, and each is checked to round-trip through getInstance().
     */
    [TestFixture]
    public class KeyPurposeIDTest
    {
        private static readonly Dictionary<KeyPurposeID, string> KeyPurposeIDMap =
            new Dictionary<KeyPurposeID, string>()
        {
            { KeyPurposeID.id_kp_documentSigning, "1.3.6.1.5.5.7.3.36" },           // RFC 9336
            { KeyPurposeID.id_kp_imUri, "1.3.6.1.5.5.7.3.40" },                     // RFC 9734
            { KeyPurposeID.id_kp_configSigning, "1.3.6.1.5.5.7.3.41" },             // RFC 9809
            { KeyPurposeID.id_kp_trustAnchorConfigSigning, "1.3.6.1.5.5.7.3.42" },  // RFC 9809
            { KeyPurposeID.id_kp_updatePackageSigning, "1.3.6.1.5.5.7.3.43" },      // RFC 9809
            { KeyPurposeID.id_kp_safetyCommunication, "1.3.6.1.5.5.7.3.44" },       // RFC 9809
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
