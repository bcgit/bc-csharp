using System;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class EGOST3410_2012SignatureTest : SimpleTest
    {
        public override string Name { get; }

        [Test]
        public override void PerformTest()
        {
            EcGOST34102012256Test();
        }

        
        public void EcGOST34102012256Test()
        {
            BigInteger r = new BigInteger("29700980915817952874371204983938256990422752107994319651632687982059210933395");
            BigInteger s = new BigInteger("574973400270084654178925310019147038455227042649098563933718999175515839552");

            BigInteger e = new BigInteger("20798893674476452017134061561508270130637142515379653289952617252661468872421");

            byte[] kData = BigIntegers.AsUnsignedByteArray(new BigInteger("53854137677348463731403841147996619241504003434302020712960838528893196233395"));
            SecureRandom k = new TestRandomBigInteger(kData);

            BigInteger mod_p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564821041");
            BigInteger mod_q = new BigInteger("57896044618658097711785492504343953927082934583725450622380973592137631069619");


            ECCurve curve = new FpCurve(
                mod_p,
                new BigInteger("7"), // a
                new BigInteger("43308876546767276905765904595650931995942111794451039583252968842033849580414"), // b
                mod_q, BigInteger.One);

            ECDomainParameters spec = new ECDomainParameters(curve,
                curve.CreatePoint(
                    new BigInteger("2"), // x
                    new BigInteger("4018974056539037503335449422937059775635739389905545080690979365213431566280")), // y
                mod_q, BigInteger.One);

            ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(
                new BigInteger("55441196065363246126355624130324183196576709222340016572108097750006097525544"), // d
                spec);

            ECPublicKeyParameters publicKey = new ECPublicKeyParameters(curve.CreatePoint(
                    new BigInteger("57520216126176808443631405023338071176630104906313632182896741342206604859403"), // x
                    new BigInteger("17614944419213781543809391949654080031942662045363639260709847859438286763994")), // y
                spec);

            ECGost3410_2012Signer signer = new ECGost3410_2012Signer();
            signer.Init(true, new ParametersWithRandom(privateKey, k));

            byte[] rev = e.ToByteArray();
            byte[] message = new byte[rev.Length];
            for (int i = 0; i != rev.Length; i++)
            {
                message[i] = rev[rev.Length - 1 - i];
            }
            BigInteger[] sig = signer.GenerateSignature(message);

            signer.Init(false, publicKey);

            if (!signer.VerifySignature(message, sig[0], sig[1]))
            {
                Fail("ECGOST3410 2012 verification failed");
            }

            if (!r.Equals(sig[0]))
            {
                Fail(
                    ": r component wrong." + Environment.NewLine
                                           + " expecting: " + r + Environment.NewLine
                                           + " got      : " + sig[0]);
            }

            if (!s.Equals(sig[1]))
            {
                Fail(
                    ": s component wrong." + Environment.NewLine
                                           + " expecting: " + s + Environment.NewLine
                                           + " got      : " + sig[1]);
            }


            // 256Bit
            {
                DerObjectIdentifier oid = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA;
                ECNamedDomainParameters ecp = new ECNamedDomainParameters(oid, ECGost3410NamedCurves.GetByOid(oid));
                ECGost3410Parameters gostParams = new ECGost3410Parameters(ecp, oid,
                    RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, null);
                ECKeyGenerationParameters parameters = new ECKeyGenerationParameters(gostParams, new SecureRandom());
                ECKeyPairGenerator engine = new ECKeyPairGenerator();
                engine.Init(parameters);
                AsymmetricCipherKeyPair pair = engine.GenerateKeyPair();
                SignatureGost12Test("ECGOST3410-2012-256", 64, pair);
            }

            // 512Bit


            {
                DerObjectIdentifier oid = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA;
                ECNamedDomainParameters ecp = new ECNamedDomainParameters(oid, ECGost3410NamedCurves.GetByOid(oid));
                ECGost3410Parameters gostParams = new ECGost3410Parameters(ecp, oid,
                    RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512, null);
                ECKeyGenerationParameters parameters = new ECKeyGenerationParameters(gostParams, new SecureRandom());
                ECKeyPairGenerator engine = new ECKeyPairGenerator();
                engine.Init(parameters);
                AsymmetricCipherKeyPair pair = engine.GenerateKeyPair();

                SignatureGost12Test("ECGOST3410-2012-512", 128, pair);

            }
        }



        private void SignatureGost12Test(String signatureAlg, int expectedSignLen, AsymmetricCipherKeyPair p)

        {
            byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };

            ECPrivateKeyParameters sKey = (ECPrivateKeyParameters)p.Private;
            ECPublicKeyParameters vKey = (ECPublicKeyParameters)p.Public;

            ECGost3410_2012Signer s = new ECGost3410_2012Signer();

            s.Init(true, sKey);
            BigInteger[] sig = s.GenerateSignature(data);


            s = new ECGost3410_2012Signer();
            s.Init(false, vKey);

            if (!s.VerifySignature(data, sig[0], sig[1]))
            {
                Fail("Signature " + signatureAlg + " did not verify");
            }

            //
            // Test with Digest signer.
            //           
            Gost3410DigestSigner digestSigner = new Gost3410DigestSigner(
                new ECGost3410_2012Signer(),
                DigestUtilities.GetDigest(((ECGost3410Parameters)vKey.Parameters).DigestParamSet));
            digestSigner.Init(true, sKey);
            digestSigner.BlockUpdate(data, 0, data.Length);
            byte[] sigBytes = digestSigner.GenerateSignature();

            if (sigBytes.Length != expectedSignLen)
            {
                Fail(signatureAlg + " signature failed at expected length");
            }

            digestSigner = new Gost3410DigestSigner(
                new ECGost3410_2012Signer(),
                DigestUtilities.GetDigest(((ECGost3410Parameters)vKey.Parameters).DigestParamSet));
            digestSigner.Init(false, vKey);
            digestSigner.BlockUpdate(data, 0, data.Length);

            if (!digestSigner.VerifySignature(sigBytes))
            {
                Fail("Signature " + signatureAlg + " did not verify");
            }
        }


    }
}