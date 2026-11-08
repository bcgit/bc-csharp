using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Isara;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// The ISARA vendor OIDs name the same structures as the legacy <see cref="Pqc.Asn1.PqcObjectIdentifiers"/> form -
    /// the same XmssKeyParams beside the algorithm and the same XmssPrivateKey / XmssPublicKey inside - so a key pair
    /// stored under those OIDs reads back on both sides.
    /// </summary>
    [TestFixture]
    public class IsaraOidKeyTests
    {
        private static PrivateKeyInfo UnderOid(PrivateKeyInfo info, DerObjectIdentifier algOid)
        {
            AlgorithmIdentifier algId = new AlgorithmIdentifier(algOid, info.PrivateKeyAlgorithm.Parameters);

            return new PrivateKeyInfo(algId, info.ParsePrivateKey());
        }

        private static SubjectPublicKeyInfo UnderOid(SubjectPublicKeyInfo info, DerObjectIdentifier algOid)
        {
            AlgorithmIdentifier algId = new AlgorithmIdentifier(algOid, info.Algorithm.Parameters);

            return new SubjectPublicKeyInfo(algId, info.PublicKey.GetBytes());
        }

        [Test]
        public void TestXmssKeyPairUnderIsaraOid()
        {
            XmssParameters parameters = new XmssParameters(4, NistObjectIdentifiers.IdSha256);
            XmssKeyPairGenerator kpg = new XmssKeyPairGenerator();

            kpg.Init(new XmssKeyGenerationParameters(new SecureRandom(), parameters));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            XmssPrivateKeyParameters privKey = (XmssPrivateKeyParameters)kp.Private;
            XmssPublicKeyParameters pubKey = (XmssPublicKeyParameters)kp.Public;

            PrivateKeyInfo privInfo = UnderOid(PrivateKeyInfoFactory.CreatePrivateKeyInfo(privKey),
                IsaraObjectIdentifiers.id_alg_xmss);
            SubjectPublicKeyInfo pubInfo = UnderOid(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey),
                IsaraObjectIdentifiers.id_alg_xmss);

            XmssPrivateKeyParameters decodedPriv = (XmssPrivateKeyParameters)PrivateKeyFactory.CreateKey(privInfo);
            XmssPublicKeyParameters decodedPub = (XmssPublicKeyParameters)PublicKeyFactory.CreateKey(pubInfo);

            Assert.AreEqual(privKey.Index, decodedPriv.Index);
            Assert.AreEqual(privKey.GetSecretKeySeed(), decodedPriv.GetSecretKeySeed());
            Assert.AreEqual(pubKey.GetRoot(), decodedPub.GetRoot());
            Assert.AreEqual(decodedPriv.GetRoot(), decodedPub.GetRoot());
        }

        [Test]
        public void TestXmssMTKeyPairUnderIsaraOid()
        {
            XmssMTParameters parameters = new XmssMTParameters(4, 2, NistObjectIdentifiers.IdSha256);
            XmssMTKeyPairGenerator kpg = new XmssMTKeyPairGenerator();

            kpg.Init(new XmssMTKeyGenerationParameters(new SecureRandom(), parameters));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            XmssMTPrivateKeyParameters privKey = (XmssMTPrivateKeyParameters)kp.Private;
            XmssMTPublicKeyParameters pubKey = (XmssMTPublicKeyParameters)kp.Public;

            PrivateKeyInfo privInfo = UnderOid(PrivateKeyInfoFactory.CreatePrivateKeyInfo(privKey),
                IsaraObjectIdentifiers.id_alg_xmssmt);
            SubjectPublicKeyInfo pubInfo = UnderOid(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey),
                IsaraObjectIdentifiers.id_alg_xmssmt);

            XmssMTPrivateKeyParameters decodedPriv = (XmssMTPrivateKeyParameters)PrivateKeyFactory.CreateKey(privInfo);
            XmssMTPublicKeyParameters decodedPub = (XmssMTPublicKeyParameters)PublicKeyFactory.CreateKey(pubInfo);

            Assert.AreEqual(privKey.Index, decodedPriv.Index);
            Assert.AreEqual(privKey.GetSecretKeySeed(), decodedPriv.GetSecretKeySeed());
            Assert.AreEqual(pubKey.GetRoot(), decodedPub.GetRoot());
            Assert.AreEqual(decodedPriv.GetRoot(), decodedPub.GetRoot());
        }
    }
}
