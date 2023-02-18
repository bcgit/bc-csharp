using NUnit.Framework;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class X509AltTest
    {
        [Test]
        public void TestX509AltTypes()
        {
            SubjectAltPublicKeyInfo subAlt = new SubjectAltPublicKeyInfo(
                new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance),
                new DerBitString(Hex.DecodeStrict("0102030405060708090807060504030201")));
            AltSignatureValue sigValAlt = new AltSignatureValue(Hex.DecodeStrict("0102030405060708090807060504030201"));

            AltSignatureAlgorithm sigAlgAlt = new AltSignatureAlgorithm(
                new AlgorithmIdentifier(PkcsObjectIdentifiers.MD5WithRsaEncryption, DerNull.Instance));
            AltSignatureAlgorithm sigAlgAlt2 = new AltSignatureAlgorithm(
                PkcsObjectIdentifiers.MD5WithRsaEncryption, DerNull.Instance);

            Assert.AreEqual(sigAlgAlt, sigAlgAlt2);

            var extGen = new X509ExtensionsGenerator();
            extGen.AddExtension(X509Extensions.SubjectAltPublicKeyInfo, false, subAlt);
            extGen.AddExtension(X509Extensions.AltSignatureAlgorithm, false, sigAlgAlt);
            extGen.AddExtension(X509Extensions.AltSignatureValue, false, sigValAlt);

            var exts = extGen.Generate();
            Assert.AreEqual(subAlt, SubjectAltPublicKeyInfo.FromExtensions(exts));
            Assert.AreEqual(sigAlgAlt, AltSignatureAlgorithm.FromExtensions(exts));
            Assert.AreEqual(sigValAlt, AltSignatureValue.FromExtensions(exts));
            Assert.AreEqual(subAlt, SubjectAltPublicKeyInfo.GetInstance(subAlt.GetEncoded()));
            Assert.AreEqual(sigAlgAlt, AltSignatureAlgorithm.GetInstance(sigAlgAlt.GetEncoded()));
            Assert.AreEqual(sigValAlt, AltSignatureValue.GetInstance(sigValAlt.GetEncoded()));
            Assert.AreEqual(subAlt, SubjectAltPublicKeyInfo.GetInstance(new DerTaggedObject(1, subAlt), true));
            Assert.AreEqual(sigAlgAlt, AltSignatureAlgorithm.GetInstance(new DerTaggedObject(1, sigAlgAlt), true));
            Assert.AreEqual(sigValAlt, AltSignatureValue.GetInstance(new DerTaggedObject(1, sigValAlt), true));
        }
    }
}
