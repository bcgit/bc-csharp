using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tests
{
    /// <summary>
    /// Unit test to verify that GOST R 34.10-2012 keys using legacy CryptoPro parameter sets
    /// are encoded with the correct GOST 2012 Algorithm OID in SubjectPublicKeyInfo (per RFC 9215).
    /// </summary>
    [TestFixture]
    public class Gost2012CryptoProSpkiTest
        : SimpleTest
    {
        public override string Name => "Gost2012CryptoProSpki";

        public override void PerformTest()
        {
            // 1. Select a legacy CryptoPro curve OID (GOST R 34.10-2001 parameter set)
            var curveOid = CryptoProObjectIdentifiers.GostR3410x2001CryptoProA; 
            var domain = ECGost3410NamedCurves.GetByOid(curveOid);
            var namedDomain = new ECNamedDomainParameters(curveOid, domain);

            // 2. Configure key parameters with a GOST 2012 (256-bit) digest OID
            var gostParameters = new ECGost3410Parameters(
                namedDomain,
                curveOid,
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256,
                null);

            // 3. Generate a key pair based on GOST 2012 parameters
            var keyGen = new ECKeyPairGenerator();
            keyGen.Init(new ECKeyGenerationParameters(gostParameters, new SecureRandom()));
            var keyPair = keyGen.GenerateKeyPair();

            // 4. Wrap the public key into SubjectPublicKeyInfo structure
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            
            string actualAlgOid = spki.Algorithm.Algorithm.Id;
            string expectedAlgOid = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256.Id;

            // 5. Assert that the algorithm OID corresponds to GOST 2012 rather than GOST 2001
            if (!expectedAlgOid.Equals(actualAlgOid))
            {
                Fail($"Expected GOST 2012 OID ({expectedAlgOid}), but got ({actualAlgOid})");
            }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}