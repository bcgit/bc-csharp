using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <remarks>Test for ECIES - Elliptic Curve Integrated Encryption Scheme</remarks>
    [TestFixture]
    public class EcIesTest
        : SimpleTest
    {
        private static readonly byte[] TwofishIV = Hex.Decode("000102030405060708090a0b0c0d0e0f");

        public EcIesTest()
        {
        }

        public override string Name => "ECIES";

        private void DoStaticTest(byte[] iv)
        {
            BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

            FpCurve curve = new FpCurve(
                new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
                new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
                new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
                n, BigInteger.One);

            ECDomainParameters parameters = new ECDomainParameters(
                curve,
                curve.DecodePoint(Hex.Decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
                n, BigInteger.One);

            ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
                "ECDH",
                new BigInteger("651056770906015076056810763456358567190100156695615665659"), // d
                parameters);

            ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
                "ECDH",
                curve.DecodePoint(Hex.Decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), // Q
                parameters);

            AsymmetricCipherKeyPair p1 = new AsymmetricCipherKeyPair(pubKey, priKey);
            AsymmetricCipherKeyPair p2 = new AsymmetricCipherKeyPair(pubKey, priKey);

            //
            // stream test
            //
            IesEngine i1 = new IesEngine(
                new ECDHBasicAgreement(),
                new Kdf2BytesGenerator(new Sha1Digest()),
                new HMac(new Sha1Digest()));
            IesEngine i2 = new IesEngine(
                new ECDHBasicAgreement(),
                new Kdf2BytesGenerator(new Sha1Digest()),
                new HMac(new Sha1Digest()));
            byte[] d = new byte[]{ 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] e = new byte[]{ 8, 7, 6, 5, 4, 3, 2, 1 };
            ICipherParameters p = new IesParameters(d, e, 64);

            i1.Init(true, p1.Private, p2.Public, p);
            i2.Init(false, p2.Private, p1.Public, p);

            byte[] message = Hex.Decode("1234567890abcdef");

            byte[] out1 = i1.ProcessBlock(message, 0, message.Length);

            if (!AreEqual(out1, Hex.Decode("609ae8fe2727572da30a1d04e3dd0530de24ee89e7313f6c400992a6")))
            {
                Fail("stream cipher test failed on enc");
            }

            byte[] out2 = i2.ProcessBlock(out1, 0, out1.Length);

            if (!AreEqual(out2, message))
            {
                Fail("stream cipher test failed");
            }

            //
            // twofish with CBC
            //
            BufferedBlockCipher c1 = new PaddedBufferedBlockCipher(
                new CbcBlockCipher(new TwofishEngine()));
            BufferedBlockCipher c2 = new PaddedBufferedBlockCipher(
                new CbcBlockCipher(new TwofishEngine()));
            i1 = new IesEngine(
                new ECDHBasicAgreement(),
                new Kdf2BytesGenerator(new Sha1Digest()),
                new HMac(new Sha1Digest()),
                c1);
            i2 = new IesEngine(
                new ECDHBasicAgreement(),
                new Kdf2BytesGenerator(new Sha1Digest()),
                new HMac(new Sha1Digest()),
                c2);
            d = new byte[]{ 1, 2, 3, 4, 5, 6, 7, 8 };
            e = new byte[]{ 8, 7, 6, 5, 4, 3, 2, 1 };
            p = new IesWithCipherParameters(d, e, 64, 128);

            if (iv != null)
            {
                p = new ParametersWithIV(p, iv);
            }

            i1.Init(true, p1.Private, p2.Public, p);
            i2.Init(false, p2.Private, p1.Public, p);

            message = Hex.Decode("1234567890abcdef");

            out1 = i1.ProcessBlock(message, 0, message.Length);

            if (!AreEqual(out1, iv == null
                ? Hex.Decode("b8a06ea5c2b9df28b58a0a90a734cde8c9c02903e5c220021fe4417410d1e53a32a71696")
                : Hex.Decode("f246b0e26a2711992cac9c590d08e45c5e730b7c0f4218bb064e27b7dd7c8a3bd8bf01c3")))
            {
                Fail("twofish cipher test failed on enc");
            }

            out2 = i2.ProcessBlock(out1, 0, out1.Length);

            if (!AreEqual(out2, message))
            {
                Fail("twofish cipher test failed");
            }
        }

        private void DoShortTest()
        {
            BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

            FpCurve curve = new FpCurve(
                new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
                new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
                new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
                n, BigInteger.One);

            ECDomainParameters parameters = new ECDomainParameters(
                curve,
                curve.DecodePoint(Hex.Decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
                n);

            ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
                new BigInteger("651056770906015076056810763456358567190100156695615665659"), // d
                parameters);

            ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
                curve.DecodePoint(Hex.Decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), // Q
                parameters);

            AsymmetricCipherKeyPair p1 = new AsymmetricCipherKeyPair(pubKey, priKey);
            AsymmetricCipherKeyPair p2 = new AsymmetricCipherKeyPair(pubKey, priKey);

            //
            // stream test - V 0
            //
            IesEngine i1 = new IesEngine(
                new ECDHBasicAgreement(),
                new Kdf2BytesGenerator(new Sha1Digest()),
                new HMac(new Sha1Digest()));
            IesEngine i2 = new IesEngine(
                new ECDHBasicAgreement(),
                new Kdf2BytesGenerator(new Sha1Digest()),
                new HMac(new Sha1Digest()));
            byte[] d = new byte[]{ 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] e = new byte[]{ 8, 7, 6, 5, 4, 3, 2, 1 };
            ICipherParameters p = new IesParameters(d, e, 64);

            i1.Init(true, p1.Private, p2.Public, p);
            i2.Init(false, p2.Private, p1.Public, p);

            byte[] message = Array.Empty<byte>();

            byte[] out1 = i1.ProcessBlock(message, 0, message.Length);

            byte[] out2 = i2.ProcessBlock(out1, 0, out1.Length);

            if (!AreEqual(out2, message))
            {
                Fail("stream cipher test failed");
            }

            try
            {
                i2.ProcessBlock(out1, 0, out1.Length - 1);
                Fail("no exception");
            }
            catch (InvalidCipherTextException ex)
            {
                if (!"Length of input must be greater than the MAC and V combined".Equals(ex.Message))
                {
                    Fail("wrong exception");
                }
            }

            // with ephemeral key pair
            // TODO Port ephemeral key pair support? (bc-java has a test case that could be copied over)
        }

        private void DoTest(AsymmetricCipherKeyPair	p1, AsymmetricCipherKeyPair	p2)
        {
            //
            // stream test
            //
            IesEngine i1 = new IesEngine(
                new ECDHBasicAgreement(),
                new Kdf2BytesGenerator(new Sha1Digest()),
                new HMac(new Sha1Digest()));
            IesEngine i2 = new IesEngine(
                new ECDHBasicAgreement(),
                new Kdf2BytesGenerator(new Sha1Digest()),
                new HMac(new Sha1Digest()));
            byte[] d = new byte[]{ 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[] e = new byte[]{ 8, 7, 6, 5, 4, 3, 2, 1 };
            IesParameters  p = new IesParameters(d, e, 64);

            i1.Init(true, p1.Private, p2.Public, p);
            i2.Init(false, p2.Private, p1.Public, p);

            byte[] message = Hex.Decode("1234567890abcdef");

            byte[] out1 = i1.ProcessBlock(message, 0, message.Length);

            byte[] out2 = i2.ProcessBlock(out1, 0, out1.Length);

            if (!AreEqual(out2, message))
            {
                Fail("stream cipher test failed");
            }

            //
            // twofish with CBC
            //
            BufferedBlockCipher c1 = new PaddedBufferedBlockCipher(
                new CbcBlockCipher(new TwofishEngine()));
            BufferedBlockCipher c2 = new PaddedBufferedBlockCipher(
                new CbcBlockCipher(new TwofishEngine()));
            i1 = new IesEngine(
                new ECDHBasicAgreement(),
                new Kdf2BytesGenerator(new Sha1Digest()),
                new HMac(new Sha1Digest()),
                c1);
            i2 = new IesEngine(
                new ECDHBasicAgreement(),
                new Kdf2BytesGenerator(new Sha1Digest()),
                new HMac(new Sha1Digest()),
                c2);
            d = new byte[]{ 1, 2, 3, 4, 5, 6, 7, 8 };
            e = new byte[]{ 8, 7, 6, 5, 4, 3, 2, 1 };
            p = new IesWithCipherParameters(d, e, 64, 128);

            i1.Init(true, p1.Private, p2.Public, p);
            i2.Init(false, p2.Private, p1.Public, p);

            message = Hex.Decode("1234567890abcdef");

            out1 = i1.ProcessBlock(message, 0, message.Length);

            out2 = i2.ProcessBlock(out1, 0, out1.Length);

            if (!AreEqual(out2, message))
            {
                Fail("twofish cipher test failed");
            }
        }

        public override void PerformTest()
        {
            DoStaticTest(null);
            DoStaticTest(TwofishIV);
            DoShortTest();

            BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

            FpCurve curve = new FpCurve(
                new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
                new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
                new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
                n, BigInteger.One);

            ECDomainParameters parameters = new ECDomainParameters(
                curve,
                curve.DecodePoint(Hex.Decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
                n, BigInteger.One);

            ECKeyPairGenerator eGen = new ECKeyPairGenerator();
            KeyGenerationParameters gParam = new ECKeyGenerationParameters(parameters, new SecureRandom());

            eGen.Init(gParam);

            AsymmetricCipherKeyPair p1 = eGen.GenerateKeyPair();
            AsymmetricCipherKeyPair p2 = eGen.GenerateKeyPair();

            DoTest(p1, p2);
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }

        // Regression for CVD ANT-2026-WZ2GJBGD: in static-key stream mode the MAC key must not be
        // recoverable from the keystream. The legacy layout placed the keystream K1 before the MAC key
        // K2, so a single known-plaintext leak of K1 (= M ^ C) also exposed the MAC key of any shorter
        // message - letting an attacker forge a valid ciphertext+tag from one observation. With K2 now
        // taken from a fixed prefix of the KDF output, that slice of the leaked keystream is no longer
        // the MAC key, so the constructed forgery must be rejected.
        [Test]
        public void ForgeryTest()
        {
            BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

            FpCurve curve = new FpCurve(
                new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
                new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
                new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
                n, BigInteger.One);

            ECDomainParameters dp = new ECDomainParameters(curve,
                curve.DecodePoint(Hex.Decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), n);

            ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
                new BigInteger("651056770906015076056810763456358567190100156695615665659"), dp);
            ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
                curve.DecodePoint(Hex.Decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), dp);

            AsymmetricCipherKeyPair p1 = new AsymmetricCipherKeyPair(pubKey, priKey);
            AsymmetricCipherKeyPair p2 = new AsymmetricCipherKeyPair(pubKey, priKey);

            int macKeyBytes = 8; // 64-bit MAC key
            // no encoding vector, so the MAC is taken over the ciphertext only (keeps the forgery construction simple)
            IesParameters param = new IesParameters(new byte[]{ 1, 2, 3, 4, 5, 6, 7, 8 }, null, macKeyBytes * 8);

            // 1. attacker observes one known-plaintext ciphertext of length L (>= macKeyBytes)
            byte[] knownPt = Hex.Decode("000102030405060708090a0b0c0d0e0f10111213"); // L = 20
            IesEngine enc = new IesEngine(new ECDHBasicAgreement(), new Kdf2BytesGenerator(new Sha1Digest()),
                new HMac(new Sha1Digest()));
            enc.Init(true, p1.Private, p2.Public, param);
            byte[] ct = enc.ProcessBlock(knownPt, 0, knownPt.Length);

            byte[] leaked = new byte[knownPt.Length]; // recovered keystream = M ^ C over the L plaintext bytes
            for (int i = 0; i != leaked.Length; i++)
            {
                leaked[i] = (byte) (knownPt[i] ^ ct[i]);
            }

            // 2. forge a shorter message, assuming the legacy keystream-then-MAC-key layout
            int forgeLen = knownPt.Length - macKeyBytes; // L'
            byte[] forgedPt = Hex.Decode("ffffffffffffffffffffffff"); // 12 bytes (= L')
            byte[] forgedC = new byte[forgeLen];
            for (int i = 0; i != forgeLen; i++)
            {
                forgedC[i] = (byte) (forgedPt[i] ^ leaked[i]); // K1' = leaked[0..L']
            }

            HMac hmac = new HMac(new Sha1Digest());
            hmac.Init(new KeyParameter(Arrays.CopyOfRange(leaked, forgeLen, forgeLen + macKeyBytes))); // K2' = leaked[L'..]
            hmac.BlockUpdate(forgedC, 0, forgedC.Length);
            byte[] forgedTag = new byte[hmac.GetMacSize()];
            hmac.DoFinal(forgedTag, 0);

            byte[] forged = Arrays.Concatenate(forgedC, forgedTag);

            // 3. the recipient must reject the forgery
            IesEngine dec = new IesEngine(new ECDHBasicAgreement(), new Kdf2BytesGenerator(new Sha1Digest()), new HMac(new Sha1Digest()));
            dec.Init(false, p2.Private, p1.Public, param);
            try
            {
                dec.ProcessBlock(forged, 0, forged.Length);
                Fail("static-key stream IES accepted a cross-message MAC forgery");
            }
            catch (InvalidCipherTextException)
            {
                // expected: K2 is a fixed prefix of the KDF output, not a recoverable slice of the keystream
            }
        }
    }
}
