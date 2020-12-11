using System;
using System.Collections;
using System.IO;
using System.Text;

using NUnit.Framework;
using Org.BouncyCastle.Asn1.Gnu;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpEdDsaTest
        : SimpleTest
    {
        private static readonly byte[] testPubKey =
            Base64.Decode(
                "mDMEX9NCKBYJKwYBBAHaRw8BAQdASPhAQySGGPMjoquv5i1IwLRSDJ2QtmLLvER2" +
                "Cm8UZyW0HkVkRFNBIDx0ZXN0LmVkZHNhQGV4YW1wbGUuY29tPoiQBBMWCAA4FiEE" +
                "sh83FOYApIfZuLp0emj2ffveCqEFAl/TQigCGwMFCwkIBwIGFQoJCAsCBBYCAwEC" +
                "HgECF4AACgkQemj2ffveCqF6XQEA2S08fb0Z6LCd9P+eajPNDm1Wrf/y/7nkNwhb" +
                "DvwiU5kBAM16UvHrzX6CvQFvc7aKvPH+4wrvRewvAGK16a4fBHEE");

        private static readonly byte[] testPrivKey =
            Base64.Decode(
                "lIYEX9NCKBYJKwYBBAHaRw8BAQdASPhAQySGGPMjoquv5i1IwLRSDJ2QtmLLvER2" +
                "Cm8UZyX+BwMC7ubvoFJTTXfOpQ3tDoys52w6tb01rHHtjKVWjXMjiyN8tXHBDC9N" +
                "UcMYViTDegBXOEgw4TIKn9mkkTDvP3xVFeMH2XBPzu9e9m8GlBODILQeRWREU0Eg" +
                "PHRlc3QuZWRkc2FAZXhhbXBsZS5jb20+iJAEExYIADgWIQSyHzcU5gCkh9m4unR6" +
                "aPZ9+94KoQUCX9NCKAIbAwULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRB6aPZ9" +
                "+94KoXpdAQDZLTx9vRnosJ30/55qM80ObVat//L/ueQ3CFsO/CJTmQEAzXpS8evN" +
                "foK9AW9ztoq88f7jCu9F7C8AYrXprh8EcQQ=");

        private static readonly char[] testPasswd = "test".ToCharArray();

        private static readonly byte[] sExprKey =
            Base64.Decode(
                "KHByb3RlY3RlZC1wcml2YXRlLWtleSAoZWNjIChjdXJ2ZSBFZDI1NTE5KShmbGFn" +
                "cyBlZGRzYSkocQogICM0MDQ4Rjg0MDQzMjQ4NjE4RjMyM0EyQUJBRkU2MkQ0OEMw" +
                "QjQ1MjBDOUQ5MEI2NjJDQkJDNDQ3NjBBNkYxNDY3MjUjKQogKHByb3RlY3RlZCBv" +
                "cGVucGdwLXMyazMtb2NiLWFlcyAoKHNoYTEgI0IwRkY2MDAzRUE4RkQ4QkIjCiAg" +
                "Ijc2OTUzNjAiKSM5NDZEREU3QTUxMzAyRUEyRDc3NDNEOTQjKSM4NDBFMTIyRTdB" +
                "RDI0RkY1MkE5RUY3QUFDQjgxRUE2CiAyMTkyQjZCMjlCOUI4N0QwNTZBOUE4MTEz" +
                "QjIzNjlEREM4QUVGMTJDNjRBN0QwOTEwM0Q1MTU1Nzc0Q0Q5RkQ4NzczQTEzCiBD" +
                "NTgwQ0Y4RkY5OEZERTU3RDVGIykocHJvdGVjdGVkLWF0ICIyMDIwMTIxMVQwOTU2" +
                "MDEiKSkp");

        private static readonly byte[] referencePubKey =
            Base64.Decode(
                "mDMEU/NfCxYJKwYBBAHaRw8BAQdAPwmJlL3ZFu1AUxl5NOSofIBzOhKA1i+AEJku" +
                "Q+47JAY=");

        private static readonly string referenceMessage = "OpenPGP";

        private static readonly byte[] referenceSignature =
            Base64.Decode(
                "iF4EABYIAAYFAlX5X5UACgkQjP3hIZeWWpr2IgEAVvkMypjiECY3vZg/2xbBMd/S" +
                "ftgr9N3lYG4NdWrtM2YBANCcT6EVJ/A44PV/IgHYLy6iyQMyZfps60iehUuuYbQE");

        private void ReferenceTest()
        {
            PgpPublicKeyRing pubKeyRing = new PgpPublicKeyRing(referencePubKey);
            PgpPublicKey publicKey = pubKeyRing.GetPublicKey();

            PgpObjectFactory pgpFact = new PgpObjectFactory(referenceSignature);
            PgpSignatureList signatureList = (PgpSignatureList)pgpFact.NextPgpObject();
            PgpSignature signature = signatureList.Get(0);
            signature.InitVerify(publicKey);
            signature.Update(Encoding.ASCII.GetBytes(referenceMessage));
            if (!signature.Verify())
            {
                Fail("signature failed to verify!");
            }
        }

        private void GenerateAndSign()
        {
            SecureRandom random = SecureRandom.GetInstance("SHA1PRNG");

            IAsymmetricCipherKeyPairGenerator keyGen = GeneratorUtilities.GetKeyPairGenerator("Ed25519");
            keyGen.Init(new ECKeyGenerationParameters(GnuObjectIdentifiers.Ed25519, random));

            AsymmetricCipherKeyPair kpSign = keyGen.GenerateKeyPair();

            PgpKeyPair eddsaKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.EdDsa, kpSign, DateTime.UtcNow);

            byte[] msg = Encoding.ASCII.GetBytes("hello world!");

            //
            // try a signature
            //
            PgpSignatureGenerator signGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.EdDsa, HashAlgorithmTag.Sha256);
            signGen.InitSign(PgpSignature.BinaryDocument, eddsaKeyPair.PrivateKey);

            signGen.Update(msg);

            PgpSignature sig = signGen.Generate();

            sig.InitVerify(eddsaKeyPair.PublicKey);
            sig.Update(msg);

            if (!sig.Verify())
            {
                Fail("signature failed to verify!");
            }

            //
            // generate a key ring
            //
            char[] passPhrase = "test".ToCharArray();
            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, eddsaKeyPair,
                "test@bouncycastle.org", SymmetricKeyAlgorithmTag.Aes256, passPhrase, true, null, null, random);

            PgpPublicKeyRing pubRing = keyRingGen.GeneratePublicKeyRing();
            PgpSecretKeyRing secRing = keyRingGen.GenerateSecretKeyRing();

            PgpPublicKeyRing pubRingEnc = new PgpPublicKeyRing(pubRing.GetEncoded());
            if (!Arrays.AreEqual(pubRing.GetEncoded(), pubRingEnc.GetEncoded()))
            {
                Fail("public key ring encoding failed");
            }

            PgpSecretKeyRing secRingEnc = new PgpSecretKeyRing(secRing.GetEncoded());
            if (!Arrays.AreEqual(secRing.GetEncoded(), secRingEnc.GetEncoded()))
            {
                Fail("secret key ring encoding failed");
            }


            //
            // try a signature using encoded key
            //
            signGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.EdDsa, HashAlgorithmTag.Sha256);
            signGen.InitSign(PgpSignature.BinaryDocument, secRing.GetSecretKey().ExtractPrivateKey(passPhrase));
            signGen.Update(msg);

            sig = signGen.Generate();
            sig.InitVerify(secRing.GetSecretKey().PublicKey);
            sig.Update(msg);

            if (!sig.Verify())
            {
                Fail("re-encoded signature failed to verify!");
            }
        }

        public override void PerformTest()
        {
            ReferenceTest();

            //
            // Read the public key
            //
            PgpPublicKeyRing pubKeyRing = new PgpPublicKeyRing(testPubKey);
            foreach (PgpSignature certification in pubKeyRing.GetPublicKey().GetSignatures())
            {
                certification.InitVerify(pubKeyRing.GetPublicKey());

                if (!certification.VerifyCertification((string)First(pubKeyRing.GetPublicKey().GetUserIds()), pubKeyRing.GetPublicKey()))
                {
                    Fail("self certification does not verify");
                }
            }

            /*if (pubKeyRing.GetPublicKey().BitStrength != 256)
            {
                Fail("incorrect bit strength returned");
            }*/

            //
            // Read the private key
            //
            PgpSecretKeyRing secretKeyRing = new PgpSecretKeyRing(testPrivKey);

            PgpPrivateKey privKey = secretKeyRing.GetSecretKey().ExtractPrivateKey(testPasswd);

            GenerateAndSign();

            //
            // sExpr
            //
            // TODO: Fails the OCB MAC check when decoding key but works otherwise
            /*byte[] msg = Encoding.ASCII.GetBytes("hello world!");

            PgpSecretKey key = PgpSecretKey.ParseSecretKeyFromSExpr(new MemoryStream(sExprKey, false), "test".ToCharArray());

            PgpSignatureGenerator signGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.EdDsa, HashAlgorithmTag.Sha256);
            signGen.InitSign(PgpSignature.BinaryDocument, key.ExtractPrivateKey(null));
            signGen.Update(msg);

            PgpSignature sig = signGen.Generate();
            sig.InitVerify(key.PublicKey);
            sig.Update(msg);

            if (!sig.Verify())
            {
                Fail("signature failed to verify!");
            }*/
        }

        private static object First(IEnumerable e)
        {
            IEnumerator n = e.GetEnumerator();
            Assert.IsTrue(n.MoveNext());
            return n.Current;
        }

        public override string Name
        {
            get { return "PgpEdDsaTest"; }
        }

        public static void Main(
            string[] args)
        {
            RunTest(new PgpECDsaTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
