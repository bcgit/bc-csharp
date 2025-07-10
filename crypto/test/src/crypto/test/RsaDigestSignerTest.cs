using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class RsaDigestSignerTest
        : SimpleTest
    {
        public override void PerformTest()
        {
            BigInteger rsaPubMod = new BigInteger(Base64.Decode("AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt"));
            BigInteger rsaPubExp = new BigInteger(Base64.Decode("EQ=="));
            BigInteger rsaPrivMod = new BigInteger(Base64.Decode("AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt"));
            BigInteger rsaPrivDP = new BigInteger(Base64.Decode("JXzfzG5v+HtLJIZqYMUefJfFLu8DPuJGaLD6lI3cZ0babWZ/oPGoJa5iHpX4Ul/7l3s1PFsuy1GhzCdOdlfRcQ=="));
            BigInteger rsaPrivDQ = new BigInteger(Base64.Decode("YNdJhw3cn0gBoVmMIFRZzflPDNthBiWy/dUMSRfJCxoZjSnr1gysZHK01HteV1YYNGcwPdr3j4FbOfri5c6DUQ=="));
            BigInteger rsaPrivExp = new BigInteger(Base64.Decode("DxFAOhDajr00rBjqX+7nyZ/9sHWRCCp9WEN5wCsFiWVRPtdB+NeLcou7mWXwf1Y+8xNgmmh//fPV45G2dsyBeZbXeJwB7bzx9NMEAfedchyOwjR8PYdjK3NpTLKtZlEJ6Jkh4QihrXpZMO4fKZWUm9bid3+lmiq43FwW+Hof8/E="));
            BigInteger rsaPrivP = new BigInteger(Base64.Decode("AJ9StyTVW+AL/1s7RBtFwZGFBgd3zctBqzzwKPda6LbtIFDznmwDCqAlIQH9X14X7UPLokCDhuAa76OnDXb1OiE="));
            BigInteger rsaPrivQ = new BigInteger(Base64.Decode("AM3JfD79dNJ5A3beScSzPtWxx/tSLi0QHFtkuhtSizeXdkv5FSba7lVzwEOGKHmW829bRoNxThDy4ds1IihW1w0="));
            BigInteger rsaPrivQinv = new BigInteger(Base64.Decode("Lt0g7wrsNsQxuDdB8q/rH8fSFeBXMGLtCIqfOec1j7FEIuYA/ACiRDgXkHa0WgN7nLXSjHoy630wC5Toq8vvUg=="));

            RsaKeyParameters rsaPublic = new RsaKeyParameters(false, rsaPubMod, rsaPubExp);
            RsaPrivateCrtKeyParameters rsaPrivate = new RsaPrivateCrtKeyParameters(rsaPrivMod, rsaPubExp, rsaPrivExp,
                rsaPrivP, rsaPrivQ, rsaPrivDP, rsaPrivDQ, rsaPrivQinv);

            CheckDigest(rsaPublic, rsaPrivate, new RipeMD128Digest(), TeleTrusTObjectIdentifiers.RipeMD128);
            CheckDigest(rsaPublic, rsaPrivate, new RipeMD160Digest(), TeleTrusTObjectIdentifiers.RipeMD160);
            CheckDigest(rsaPublic, rsaPrivate, new RipeMD256Digest(), TeleTrusTObjectIdentifiers.RipeMD256);

            CheckDigest(rsaPublic, rsaPrivate, new Sha1Digest(), X509ObjectIdentifiers.IdSha1);
            CheckDigest(rsaPublic, rsaPrivate, new Sha224Digest(), NistObjectIdentifiers.IdSha224);
            CheckDigest(rsaPublic, rsaPrivate, new Sha256Digest(), NistObjectIdentifiers.IdSha256);
            CheckDigest(rsaPublic, rsaPrivate, new Sha384Digest(), NistObjectIdentifiers.IdSha384);
            CheckDigest(rsaPublic, rsaPrivate, new Sha512Digest(), NistObjectIdentifiers.IdSha512);
            CheckDigest(rsaPublic, rsaPrivate, new Sha512tDigest(224), NistObjectIdentifiers.IdSha512_224);
            CheckDigest(rsaPublic, rsaPrivate, new Sha512tDigest(256), NistObjectIdentifiers.IdSha512_256);

            CheckDigest(rsaPublic, rsaPrivate, new Sha3Digest(224), NistObjectIdentifiers.IdSha3_224);
            CheckDigest(rsaPublic, rsaPrivate, new Sha3Digest(256), NistObjectIdentifiers.IdSha3_256);
            CheckDigest(rsaPublic, rsaPrivate, new Sha3Digest(384), NistObjectIdentifiers.IdSha3_384);
            CheckDigest(rsaPublic, rsaPrivate, new Sha3Digest(512), NistObjectIdentifiers.IdSha3_512);

            CheckDigest(rsaPublic, rsaPrivate, new MD2Digest(), PkcsObjectIdentifiers.MD2);
            CheckDigest(rsaPublic, rsaPrivate, new MD4Digest(), PkcsObjectIdentifiers.MD4);
            CheckDigest(rsaPublic, rsaPrivate, new MD5Digest(), PkcsObjectIdentifiers.MD5);

            CheckNullDigest(rsaPublic, rsaPrivate, new Sha1Digest(), X509ObjectIdentifiers.IdSha1);
            CheckNullDigest(rsaPublic, rsaPrivate, new Sha256Digest(), NistObjectIdentifiers.IdSha256);

            // Null format test
            var signer = CreatePrehashSigner();
            signer.Init(forSigning: true, rsaPrivate);
            signer.BlockUpdate(new byte[20], 0, 20);

            try
            {
                signer.GenerateSignature();
                Fail("no exception");
            }
            catch (CryptoException e)
            {
                IsTrue(e.Message.StartsWith("unable to encode signature: "));
            }
        }

        private void CheckDigest(RsaKeyParameters rsaPublic, RsaPrivateCrtKeyParameters rsaPrivate, IDigest digest,
            DerObjectIdentifier digOid)
        {
            byte[] msg = { 1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23 };

            RsaDigestSigner signer = new RsaDigestSigner(digest);
            signer.Init(forSigning: true, rsaPrivate);
            signer.BlockUpdate(msg, 0, msg.Length);
            byte[] sig = signer.GenerateSignature();

            signer = new RsaDigestSigner(digest, digOid);
            signer.Init(forSigning: false, rsaPublic);
            signer.BlockUpdate(msg, 0, msg.Length);
            if (!signer.VerifySignature(sig))
            {
                Fail("RSA Digest Signer failed.");
            }
        }

        private void CheckNullDigest(RsaKeyParameters rsaPublic, RsaPrivateCrtKeyParameters rsaPrivate, IDigest digest,
            DerObjectIdentifier digOid)
        {
            byte[] msg = { 1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23 };
            byte[] hash = DigestUtilities.DoFinal(digest, msg);

            DigestInfo digInfo = new DigestInfo(new AlgorithmIdentifier(digOid, DerNull.Instance), hash);
            byte[] infoEnc = digInfo.GetEncoded();

            var signer = CreatePrehashSigner();
            signer.Init(forSigning: true, rsaPrivate);
            signer.BlockUpdate(infoEnc, 0, infoEnc.Length);

            byte[] sig = signer.GenerateSignature();

            signer = new RsaDigestSigner(digest, digOid);
            signer.Init(forSigning: false, rsaPublic);
            signer.BlockUpdate(msg, 0, msg.Length);
            if (!signer.VerifySignature(sig))
            {
                Fail("NONE - RSA Digest Signer failed.");
            }

            signer = CreatePrehashSigner();
            signer.Init(forSigning: false, rsaPublic);
            signer.BlockUpdate(infoEnc, 0, infoEnc.Length);
            if (!signer.VerifySignature(sig))
            {
                Fail("NONE - RSA Digest Signer failed.");
            }
        }

        public override string Name => "RsaDigestSigner";

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }

        private static RsaDigestSigner CreatePrehashSigner() =>
            new RsaDigestSigner(new NullDigest(), (AlgorithmIdentifier)null);
    }
}
