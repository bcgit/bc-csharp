using System;
using NUnit.Framework;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class ECGOST3410_2012Test:SimpleTest
    {
        public override string Name
        {
            get { return "ECGOST3410-2012-Test"; }
        }

        public SimpleTestResult EncodeRecodePublicKey()
        {

            DerObjectIdentifier oid = ECGost3410NamedCurves.GetOid("Tc26-Gost-3410-12-512-paramSetA");
            ECNamedDomainParameters ecp = new ECNamedDomainParameters(oid, ECGost3410NamedCurves.GetByOid(oid));
            ECGOST3410Parameters gostParams = new ECGOST3410Parameters(ecp, oid, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512,null);
            ECKeyGenerationParameters paramameters = new ECKeyGenerationParameters(gostParams, new SecureRandom());
            ECKeyPairGenerator engine = new ECKeyPairGenerator();
            engine.Init(paramameters);
            AsymmetricCipherKeyPair pair = engine.GenerateKeyPair();

            ECPublicKeyParameters generatedKeyParameters = (ECPublicKeyParameters)pair.Public;
            ECPublicKeyParameters keyParameters = generatedKeyParameters;


            //
            // Continuously encode/decode the key and check for loss of information.
            //          
                for (int t = 0; t < 3; t++)
                {

                    SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyParameters);
                    keyParameters = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(info);

                    { // Specifically cast and test gost parameters.
                        ECGOST3410Parameters gParam = (ECGOST3410Parameters)generatedKeyParameters.Parameters;
                        ECGOST3410Parameters rParam = (ECGOST3410Parameters)keyParameters.Parameters;


                        bool ok = SafeEquals(gParam.DigestParamSet, rParam.DigestParamSet) &&
                            SafeEquals(gParam.EncryptionParamSet, rParam.EncryptionParamSet) &&
                            SafeEquals(gParam.PublicKeyParamSet, rParam.PublicKeyParamSet);

                        if (!ok)
                        {
                            return new SimpleTestResult(false, "GOST parameters does not match");
                        }

                    }

                    if (!((ECGOST3410Parameters)keyParameters.Parameters).Name.Equals(
                        ((ECGOST3410Parameters)generatedKeyParameters.Parameters).Name))
                    {
                        return new SimpleTestResult(false, "Name does not match");
                    }


                    if (keyParameters.IsPrivate != generatedKeyParameters.IsPrivate)
                    {
                        return new SimpleTestResult(false, "isPrivate does not match");
                    }

                    if (!Arrays.AreEqual(keyParameters.Q.GetEncoded(true), generatedKeyParameters.Q.GetEncoded(true)))
                    {
                        return new SimpleTestResult(false, "Q does not match");
                    }

                    if (!keyParameters.Parameters.Curve.Equals(generatedKeyParameters.Parameters.Curve))
                    {
                        return new SimpleTestResult(false, "Curve does not match");
                    }

                    if (!Arrays.AreEqual(
                        keyParameters.Parameters.G.GetEncoded(true),
                        generatedKeyParameters.Parameters.G.GetEncoded(true)))
                    {
                        return new SimpleTestResult(false, "G does not match");
                    }

                    if (!keyParameters.Parameters.H.Equals(generatedKeyParameters.Parameters.H))
                    {
                        return new SimpleTestResult(false, "H does not match");
                    }

                    if (!keyParameters.Parameters.HInv.Equals(generatedKeyParameters.Parameters.HInv))
                    {
                        return new SimpleTestResult(false, "Hinv does not match");
                    }

                    if (!keyParameters.Parameters.N.Equals(generatedKeyParameters.Parameters.N))
                    {
                        return new SimpleTestResult(false, "N does not match");
                    }

                    if (!Arrays.AreEqual(keyParameters.Parameters.GetSeed(), generatedKeyParameters.Parameters.GetSeed()))
                    {
                        return new SimpleTestResult(false, "Seed does not match");
                    }
                }
                return new SimpleTestResult(true, null);
            

        }


        private SimpleTestResult EncodeRecodePrivateKey()
        {
           
                DerObjectIdentifier oid = ECGost3410NamedCurves.GetOid("Tc26-Gost-3410-12-512-paramSetA");
                ECNamedDomainParameters ecp = new ECNamedDomainParameters(oid, ECGost3410NamedCurves.GetByOid(oid));
                ECGOST3410Parameters gostParams = new ECGOST3410Parameters(ecp, oid, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512,null);
                ECKeyGenerationParameters parameters = new ECKeyGenerationParameters(gostParams, new SecureRandom());
                ECKeyPairGenerator engine = new ECKeyPairGenerator();
                engine.Init(parameters);
                AsymmetricCipherKeyPair pair = engine.GenerateKeyPair();

                ECPrivateKeyParameters generatedKeyParameters = (ECPrivateKeyParameters)pair.Private;
                ECPrivateKeyParameters keyParameters = generatedKeyParameters;


                //
                // Continuously encode/decode the key and check for loss of information.
                //


                for (int t = 0; t < 3; t++)
                {
                    PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyParameters);
                    keyParameters = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(info);

                    { // Specifically cast and test gost parameters.
                        ECGOST3410Parameters gParam = (ECGOST3410Parameters)generatedKeyParameters.Parameters;
                        ECGOST3410Parameters rParam = (ECGOST3410Parameters)keyParameters.Parameters;

                        bool ok = SafeEquals(gParam.DigestParamSet, rParam.DigestParamSet) &&
                            SafeEquals(gParam.EncryptionParamSet, rParam.EncryptionParamSet) &&
                            SafeEquals(gParam.PublicKeyParamSet, rParam.PublicKeyParamSet);

                        if (!ok)
                        {
                            return new SimpleTestResult(false, "GOST parameters does not match");
                        }

                    }

                    if (keyParameters.IsPrivate != generatedKeyParameters.IsPrivate)
                    {
                        return new SimpleTestResult(false, "isPrivate does not match");
                    }

                    if (!keyParameters.D.Equals(generatedKeyParameters.D))
                    {
                        return new SimpleTestResult(false, "D does not match");
                    }

                    if (!((ECGOST3410Parameters)keyParameters.Parameters).Name.Equals(
                        ((ECGOST3410Parameters)generatedKeyParameters.Parameters).Name))
                    {
                        return new SimpleTestResult(false, "Name does not match");
                    }

                    if (!keyParameters.Parameters.Curve.Equals(generatedKeyParameters.Parameters.Curve))
                    {
                        return new SimpleTestResult(false, "Curve does not match");
                    }

                    if (!Arrays.AreEqual(
                        keyParameters.Parameters.G.GetEncoded(true),
                        generatedKeyParameters.Parameters.G.GetEncoded(true)))
                    {
                        return new SimpleTestResult(false, "G does not match");
                    }

                    if (!keyParameters.Parameters.H.Equals(generatedKeyParameters.Parameters.H))
                    {
                        return new SimpleTestResult(false, "H does not match");
                    }

                    if (!keyParameters.Parameters.HInv.Equals(generatedKeyParameters.Parameters.HInv))
                    {
                        return new SimpleTestResult(false, "Hinv does not match");
                    }

                    if (!keyParameters.Parameters.N.Equals(generatedKeyParameters.Parameters.N))
                    {
                        return new SimpleTestResult(false, "N does not match");
                    }

                    if (!Arrays.AreEqual(keyParameters.Parameters.GetSeed(), generatedKeyParameters.Parameters.GetSeed()))
                    {
                        return new SimpleTestResult(false, "Seed does not match");
                    }
                }


          
            return new SimpleTestResult(true, null);
        }

        private SimpleTestResult DecodeJCEPublic()
        {
            byte[] pub256 = Hex.Decode("3068302106082a85030701010101301506092a850307010201010106082a850307010102020343000440292335c87d892510c35a033819a13e2b0dc606d911676af2bad8872d74a4b7bae6c729e98ace04c3dee626343f794731e1489edb7bc26f1c8c56e1448c96501a");

                ECPublicKeyParameters pkInfo = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(pub256);

                if (pkInfo.IsPrivate)
                {
                    return new SimpleTestResult(false, "isPrivate should be false");
                }

                if (
                    !Arrays.AreEqual(
                        pkInfo.Q.GetEncoded(true),
                        Hex.Decode("02bab7a4742d87d8baf26a6711d906c60d2b3ea11938035ac31025897dc8352329")))
                {
                    return new SimpleTestResult(false, "Q does not match");
                }

                if (!((ECGOST3410Parameters)pkInfo.Parameters).PublicKeyParamSet.ToString().Equals("1.2.643.7.1.2.1.1.1"))
                {
                    return new SimpleTestResult(false, "PublicKeyParamSet does not match");
                }

                if (!((ECGOST3410Parameters)pkInfo.Parameters).DigestParamSet.ToString().Equals("1.2.643.7.1.1.2.2"))
                {
                    return new SimpleTestResult(false, "DigestParamSet does not match");
                }

                if (((ECGOST3410Parameters)pkInfo.Parameters).EncryptionParamSet != null)
                {
                    return new SimpleTestResult(false, "EncryptionParamSet is not null");
                }


                byte[] pub512 = Hex.Decode("3081aa302106082a85030701010102301506092a850307010201020106082a850307010102030381840004818043ccc22692ee8a1870c7c9de0566d7e3a494cf0e3c80f9e8852a3d1ec10d2a829d357253e0864aee2eaacd5e2d327578dee771f62f24decfd6358e06199efe540e7912db43c4c80fe0fd31f7f67a862f9d44fd0075cfee6e3d638c7520063d26311ef962547e8129fb8c5b194e129370cd30313884b4a60872254a10772fe595");

                pkInfo = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(pub512);

                if (pkInfo.IsPrivate)
                {
                    return new SimpleTestResult(false, "isPrivate should be true");
                }

                if (
                    !Arrays.AreEqual(
                        pkInfo.Q.GetEncoded(true),
                        Hex.Decode("0254fe9e19068e35d6cfde242ff671e7de7875322d5ecdaa2eee4a86e05372359d822a0dc11e3d2a85e8f9803c0ecf94a4e3d76605dec9c770188aee9226c2cc43")))
                {
                    return new SimpleTestResult(false, "Q does not match");
                }


                if (!((ECGOST3410Parameters)pkInfo.Parameters).PublicKeyParamSet.ToString().Equals("1.2.643.7.1.2.1.2.1"))
                {
                    return new SimpleTestResult(false, "PublicKeyParamSet does not match");
                }

                if (!((ECGOST3410Parameters)pkInfo.Parameters).DigestParamSet.ToString().Equals("1.2.643.7.1.1.2.3"))
                {
                    return new SimpleTestResult(false, "DigestParamSet does not match");
                }

                if (((ECGOST3410Parameters)pkInfo.Parameters).EncryptionParamSet != null)
                {
                    return new SimpleTestResult(false, "EncryptionParamSet is not null");
                }

           

            return new SimpleTestResult(true, null);
        }

        private SimpleTestResult DecodeJCEPrivate()
        {
            byte[] priv256 = Hex.Decode("304a020100302106082a85030701010101301506092a850307010201010106082a8503070101020204220420fe75ba328d5439ed4859e6dc7e6ca2e9aab0818f094eddeb0d57d1c16a90762b");          
                ECPrivateKeyParameters pkInfo = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(priv256);

                if (!pkInfo.IsPrivate)
                {
                    return new SimpleTestResult(false, "isPrivate should be true");
                }

                if (
                    !Arrays.AreEqual(
                        Hex.Decode("2b76906ac1d1570debdd4e098f81b0aae9a26c7edce65948ed39548d32ba75fe"),
                        pkInfo.D.ToByteArray()))
                {
                    return new SimpleTestResult(false, "D does not match");
                }

                if (!((ECGOST3410Parameters)pkInfo.Parameters).PublicKeyParamSet.ToString().Equals("1.2.643.7.1.2.1.1.1"))
                {
                    return new SimpleTestResult(false, "PublicKeyParamSet does not match");
                }

                if (!((ECGOST3410Parameters)pkInfo.Parameters).DigestParamSet.ToString().Equals("1.2.643.7.1.1.2.2"))
                {
                    return new SimpleTestResult(false, "DigestParamSet does not match");
                }

                if (((ECGOST3410Parameters)pkInfo.Parameters).EncryptionParamSet != null)
                {
                    return new SimpleTestResult(false, "EncryptionParamSet is not null");
                }


                byte[] priv512 = Hex.Decode("306a020100302106082a85030701010102301506092a850307010201020106082a85030701010203044204402fc35576152f6e873236608b592b4b98d0793bf5184f8dc4a99512be703716991a96061ef46aceeae5319b5c69e6fcbfa7e339207878597ce50f9b7cbf857ff1");

                pkInfo = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(priv512);

                if (!pkInfo.IsPrivate)
                {
                    return new SimpleTestResult(false, "isPrivate should be true");
                }

                if (
                    !Arrays.AreEqual(
                        Hex.Decode("00f17f85bf7c9b0fe57c5978782039e3a7bffce6695c9b31e5eace6af41e06961a99163770be1295a9c48d4f18f53b79d0984b2b598b603632876e2f157655c32f"),
                        pkInfo.D.ToByteArray()))
                {
                    return new SimpleTestResult(false, "D does not match");
                }

                if (!((ECGOST3410Parameters)pkInfo.Parameters).PublicKeyParamSet.ToString().Equals("1.2.643.7.1.2.1.2.1"))
                {
                    return new SimpleTestResult(false, "PublicKeyParamSet does not match");
                }

                if (!((ECGOST3410Parameters)pkInfo.Parameters).DigestParamSet.ToString().Equals("1.2.643.7.1.1.2.3"))
                {
                    return new SimpleTestResult(false, "DigestParamSet does not match");
                }

                if (((ECGOST3410Parameters)pkInfo.Parameters).EncryptionParamSet != null)
                {
                    return new SimpleTestResult(false, "EncryptionParamSet is not null");
                }

           

            return new SimpleTestResult(true, null);
        }



        public SimpleTestResult EncodeDecodePrivateLW(String oidStr, DerObjectIdentifier digest)
        {
            DerObjectIdentifier oid = ECGost3410NamedCurves.GetOid(oidStr);
            ECNamedDomainParameters ecp = new ECNamedDomainParameters(oid, ECGost3410NamedCurves.GetByOid(oid));
            ECGOST3410Parameters gostParams = new ECGOST3410Parameters(ecp, oid, digest, null);
            ECKeyGenerationParameters parameters = new ECKeyGenerationParameters(gostParams, new SecureRandom());
            ECKeyPairGenerator engine = new ECKeyPairGenerator();
            engine.Init(parameters);
            AsymmetricCipherKeyPair pair = engine.GenerateKeyPair();


            ECPrivateKeyParameters generatedKeyParameters = (ECPrivateKeyParameters) pair.Private;

            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(generatedKeyParameters);

            ECPrivateKeyParameters recoveredKeyParameters = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(info);


            { // Specifically cast and test gost parameters.
                ECGOST3410Parameters gParam = (ECGOST3410Parameters)generatedKeyParameters.Parameters;
                ECGOST3410Parameters rParam = (ECGOST3410Parameters)recoveredKeyParameters.Parameters;

                bool ok = SafeEquals(gParam.DigestParamSet, rParam.DigestParamSet) &&
                    SafeEquals(gParam.EncryptionParamSet, rParam.EncryptionParamSet) &&
                    SafeEquals(gParam.PublicKeyParamSet, rParam.PublicKeyParamSet);

                if (!ok)
                {
                    return new SimpleTestResult(false, "GOST parameters does not match");
                }

            }


            if (recoveredKeyParameters.IsPrivate != generatedKeyParameters.IsPrivate)
            {
                return new SimpleTestResult(false, "isPrivate does not match");
            }

            if (!((ECGOST3410Parameters)recoveredKeyParameters.Parameters).Name.Equals(
                ((ECGOST3410Parameters)generatedKeyParameters.Parameters).Name))
            {
                return new SimpleTestResult(false, "Name does not match");
            }


            if (!recoveredKeyParameters.D.Equals(generatedKeyParameters.D))
            {
                return new SimpleTestResult(false, "D does not match");
            }

            if (!recoveredKeyParameters.Parameters.Curve.Equals(generatedKeyParameters.Parameters.Curve))
            {
                return new SimpleTestResult(false, "Curve does not match");
            }

            if (!Arrays.AreEqual(
                recoveredKeyParameters.Parameters.G.GetEncoded(true),
                generatedKeyParameters.Parameters.G.GetEncoded(true)))
            {
                return new SimpleTestResult(false, "G does not match");
            }

            if (!recoveredKeyParameters.Parameters.H.Equals(generatedKeyParameters.Parameters.H))
            {
                return new SimpleTestResult(false, "H does not match");
            }

            if (!recoveredKeyParameters.Parameters.HInv.Equals(generatedKeyParameters.Parameters.HInv))
            {
                return new SimpleTestResult(false, "Hinv does not match");
            }

            if (!recoveredKeyParameters.Parameters.N.Equals(generatedKeyParameters.Parameters.N))
            {
                return new SimpleTestResult(false, "N does not match");
            }

            if (!Arrays.AreEqual(recoveredKeyParameters.Parameters.GetSeed(), generatedKeyParameters.Parameters.GetSeed()))
            {
                return new SimpleTestResult(false, "Seed does not match");
            }

            return new SimpleTestResult(true, null);
        }

        public SimpleTestResult EncodeDecodePublicLW(string oidStr, DerObjectIdentifier digest)
        {         
            DerObjectIdentifier oid = ECGost3410NamedCurves.GetOid(oidStr);
            ECNamedDomainParameters ecp = new ECNamedDomainParameters(oid, ECGost3410NamedCurves.GetByOid(oid));
            ECGOST3410Parameters gostParams = new ECGOST3410Parameters(ecp,oid,digest,null);
            ECKeyGenerationParameters parameters = new ECKeyGenerationParameters(gostParams, new SecureRandom());
            ECKeyPairGenerator engine = new ECKeyPairGenerator();
            engine.Init(parameters);
            AsymmetricCipherKeyPair pair = engine.GenerateKeyPair();
            ECPublicKeyParameters generatedKeyParameters = (ECPublicKeyParameters)pair.Public;

            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(generatedKeyParameters);

            ECPublicKeyParameters recoveredKeyParameters = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(info);

            { // Specifically cast and test gost parameters.
                ECGOST3410Parameters gParam = (ECGOST3410Parameters)generatedKeyParameters.Parameters;
                ECGOST3410Parameters rParam = (ECGOST3410Parameters)recoveredKeyParameters.Parameters;


                bool ok = SafeEquals(gParam.DigestParamSet, rParam.DigestParamSet) &&
                             SafeEquals(gParam.EncryptionParamSet, rParam.EncryptionParamSet) &&
                             SafeEquals(gParam.PublicKeyParamSet, rParam.PublicKeyParamSet);

                if (!ok)
                {
                    return new SimpleTestResult(false, "GOST parameters does not match");
                }

            }

            if (!((ECGOST3410Parameters)recoveredKeyParameters.Parameters).Name.Equals(
                   ((ECGOST3410Parameters)generatedKeyParameters.Parameters).Name))
            {
                return new SimpleTestResult(false, "Name does not match");
            }


            if (recoveredKeyParameters.IsPrivate != generatedKeyParameters.IsPrivate)
            {
                return new SimpleTestResult(false, "isPrivate does not match");
            }

            if (!Arrays.AreEqual(recoveredKeyParameters.Q.GetEncoded(true), generatedKeyParameters.Q.GetEncoded(true)))
            {
                return new SimpleTestResult(false, "Q does not match");
            }

            if (!recoveredKeyParameters.Parameters.Curve.Equals(generatedKeyParameters.Parameters.Curve))
            {
                return new SimpleTestResult(false, "Curve does not match");
            }

            if (!Arrays.AreEqual(
                recoveredKeyParameters.Parameters.G.GetEncoded(true),
                generatedKeyParameters.Parameters.G.GetEncoded(true)))
            {
                return new SimpleTestResult(false, "G does not match");
            }

            if (!recoveredKeyParameters.Parameters.H.Equals(generatedKeyParameters.Parameters.H))
            {
                return new SimpleTestResult(false, "H does not match");
            }

            if (!recoveredKeyParameters.Parameters.HInv.Equals(generatedKeyParameters.Parameters.HInv))
            {
                return new SimpleTestResult(false, "Hinv does not match");
            }

            if (!recoveredKeyParameters.Parameters.N.Equals(generatedKeyParameters.Parameters.N))
            {
                return new SimpleTestResult(false, "N does not match");
            }

            if (!Arrays.AreEqual(recoveredKeyParameters.Parameters.GetSeed(), generatedKeyParameters.Parameters.GetSeed()))
            {
                return new SimpleTestResult(false, "Seed does not match");
            }

            return new SimpleTestResult(true, null);          
        }

        [Test]
        public override void PerformTest()
        {

            SimpleTestResult str = EncodeDecodePublicLW("Tc26-Gost-3410-12-512-paramSetA", RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);
            if (!str.IsSuccessful())
            {
                Fail(str.ToString(), str.GetException());
            }

            str = EncodeDecodePrivateLW("Tc26-Gost-3410-12-512-paramSetA", RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);
            if (!str.IsSuccessful())
            {
                Fail(str.ToString(), str.GetException());
            }


            str = EncodeDecodePublicLW("Tc26-Gost-3410-12-256-paramSetA", RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
            if (!str.IsSuccessful())
            {
                Fail(str.ToString(), str.GetException());
            }

            str = EncodeDecodePrivateLW("Tc26-Gost-3410-12-256-paramSetA", RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
            if (!str.IsSuccessful())
            {
                Fail(str.ToString(), str.GetException());
            }


            str = DecodeJCEPrivate();
            if (!str.IsSuccessful())
            {
                Fail(str.ToString(), str.GetException());
            }

            str = DecodeJCEPublic();
            if (!str.IsSuccessful())
            {
                Fail(str.ToString(), str.GetException());
            }

            str = EncodeRecodePrivateKey();
            if (!str.IsSuccessful())
            {
                Fail(str.ToString(), str.GetException());
            }

            str = EncodeRecodePublicKey();
            if (!str.IsSuccessful())
            {
                Fail(str.ToString(), str.GetException());
            }

        }

        private bool SafeEquals(object left, object right)
        {
            if (left == null || right == null)
            {
                return left == null && right == null;
            }

            return left.Equals(right);
        }
    }
}