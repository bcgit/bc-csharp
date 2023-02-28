using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PolicyUrlTest
    {
        [Test]
        public void TestGetUrl()
        {
            PolicyUrl policyUrl = new PolicyUrl(true, "https://bouncycastle.org/policy/alice.txt");
            Assert.IsTrue(policyUrl.IsCritical());
            Assert.AreEqual("https://bouncycastle.org/policy/alice.txt", policyUrl.Url);

            policyUrl = new PolicyUrl(false, "https://bouncycastle.org/policy/bob.txt");
            Assert.IsFalse(policyUrl.IsCritical());
            Assert.AreEqual("https://bouncycastle.org/policy/bob.txt", policyUrl.Url);
        }

        [Test]
        public void TestParsingFromSignature()
        {
            string signatureWithPolicyUrl = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "iKQEHxYKAFYFAmIRIAgJEDXXpSQjWzWvFiEEVSc3S9X9kRTsyfjqNdelJCNbNa8u\n" +
                "Gmh0dHBzOi8vZXhhbXBsZS5vcmcvfmFsaWNlL3NpZ25pbmctcG9saWN5LnR4dAAA\n" +
                "NnwBAImA2KdiS/7kLWoQpwc+A6N2PtAvLxG0gkZmGzYgRWvGAP9g4GLAA/GQ0plr\n" +
                "Xn7uLnOG49S1fFA9P+R1Dd8Qoa4+Dg==\n" +
                "=OPUu\n" +
                "-----END PGP SIGNATURE-----\n";

            MemoryStream byteIn = new MemoryStream(Strings.ToByteArray(signatureWithPolicyUrl), false);
            ArmoredInputStream armorIn = new ArmoredInputStream(byteIn);
            PgpObjectFactory objectFactory = new PgpObjectFactory(armorIn);

            PgpSignatureList signatures = (PgpSignatureList)objectFactory.NextPgpObject();
            PgpSignature signature = signatures[0];

            PolicyUrl policyUrl = signature.GetHashedSubPackets().GetPolicyUrl();
            Assert.AreEqual("https://example.org/~alice/signing-policy.txt", policyUrl.Url);

            PolicyUrl other = new PolicyUrl(false, "https://example.org/~alice/signing-policy.txt");

            MemoryStream first = new MemoryStream();
            policyUrl.Encode(first);

            MemoryStream second = new MemoryStream();
            other.Encode(second);

            Assert.IsTrue(Arrays.AreEqual(first.ToArray(), second.ToArray()));
        }
    }
}
