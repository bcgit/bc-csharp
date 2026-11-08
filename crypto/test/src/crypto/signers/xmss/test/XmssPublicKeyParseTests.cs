using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Isara;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// The XMSS / XMSS^MT public key decode path in <see cref="PublicKeyFactory"/>. The raw RFC 9802 / RFC 8391
    /// SubjectPublicKeyInfo form prefixes the key material with a 4-octet parameter-set OID; a key whose material is
    /// shorter than that prefix, or which carries a valid OID but truncated root / seed material, is reported as an
    /// <see cref="ArgumentException"/> rather than as an index error out of the decoder.
    /// </summary>
    /// <remarks>Java reports these as IOException, the contract of its factories; here it is ArgumentException.
    /// </remarks>
    [TestFixture]
    public class XmssPublicKeyParseTests
    {
        // every OID that routes through the XMSS / XMSS^MT half of PublicKeyFactory
        private static readonly DerObjectIdentifier[] XmssOids =
        {
            PqcObjectIdentifiers.xmss,
            IsaraObjectIdentifiers.id_alg_xmss,
            IanaObjectIdentifiers.id_alg_xmss_hashsig,
            PqcObjectIdentifiers.xmss_mt,
            IsaraObjectIdentifiers.id_alg_xmssmt,
            IanaObjectIdentifiers.id_alg_xmssmt_hashsig,
        };

        [Test]
        public void TestShortPublicKeyRejected()
        {
            // key material shorter than the 4-octet OID prefix
            for (int i = 0; i != XmssOids.Length; i++)
            {
                for (int len = 0; len != 4; len++)
                {
                    SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(XmssOids[i]),
                        new byte[len]);

                    Assert.Throws<ArgumentException>(() => PublicKeyFactory.CreateKey(spki),
                        "expected ArgumentException for " + XmssOids[i] + " with key length " + len);
                }
            }
        }

        [Test]
        public void TestTruncatedPublicKeyRejected()
        {
            // a valid 4-octet parameter-set OID (0x01) followed by truncated root / seed material
            byte[] keyEnc = new byte[]{ 0, 0, 0, 1, 0, 0, 0, 0 };
            for (int i = 0; i != XmssOids.Length; i++)
            {
                SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(XmssOids[i]), keyEnc);

                Assert.Throws<ArgumentException>(() => PublicKeyFactory.CreateKey(spki),
                    "expected ArgumentException for truncated " + XmssOids[i]);
            }
        }
    }
}
