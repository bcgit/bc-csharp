using System;

using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    public class RegressionTest
    {
        public static ITest[] tests = new ITest[]
        {
            new AesTest(),
            new AesLightTest(),
            new AesFastTest(),
            new AesWrapTest(),
            new DesTest(),
            new DesEdeTest(),
            new ModeTest(),
            new PaddingTest(),
            new DHTest(),
            new ElGamalTest(),
            new DsaTest(),
            new ECTest(),
            new DeterministicDsaTest(),
            new Gost3410Test(),
            new ECGost3410Test(),
            new EcIesTest(),
            new EcNrTest(),
            new MacTest(),
            new Gost28147MacTest(),
            new RC2Test(),
            new RC2WrapTest(),
            new RC4Test(),
            new RC5Test(),
            new RC6Test(),
            new RijndaelTest(),
            new SerpentTest(),
            new TnepresTest(),
            new CamelliaTest(),
            new CamelliaLightTest(),
            new DigestRandomNumberTest(),
            new SkipjackTest(),
            new BlowfishTest(),
            new TwofishTest(),
            new Threefish256Test(),
            new Threefish512Test(),
            new Threefish1024Test(),
            new SkeinDigestTest(),
            new SkeinMacTest(),
            new Cast5Test(),
            new Cast6Test(),
            new Gost28147Test(),
            new IdeaTest(),
            new RsaBlindedTest(),
            new RsaTest(),
            new ISO9796Test(),
            new ISO9797Alg3MacTest(),
            new MD2DigestTest(),
            new MD4DigestTest(),
            new MD5DigestTest(),
            new PssBlindTest(),
            new Sha1DigestTest(),
            new Sha224DigestTest(),
            new Sha256DigestTest(),
            new Sha384DigestTest(),
            new Sha512DigestTest(),
            new Sha512t224DigestTest(),
            new Sha512t256DigestTest(),
            new Sha3DigestTest(),
            new RipeMD128DigestTest(),
            new RipeMD160DigestTest(),
            new RipeMD256DigestTest(),
            new RipeMD320DigestTest(),
            new TigerDigestTest(),
            new Gost3411DigestTest(),
            new WhirlpoolDigestTest(),
            new MD5HMacTest(),
            new Sha1HMacTest(),
            new Sha224HMacTest(),
            new Sha256HMacTest(),
            new Sha384HMacTest(),
            new Sha512HMacTest(),
            new RipeMD128HMacTest(),
            new RipeMD160HMacTest(),
            new OaepTest(),
            new PssTest(),
            new CTSTest(),
            new CcmTest(),
            new Pkcs5Test(),
            new Pkcs12Test(),
            new Kdf1GeneratorTest(),
            new Kdf2GeneratorTest(),
            new Mgf1GeneratorTest(),
            new HkdfGeneratorTest(),
            new DHKekGeneratorTest(),
            new ECDHKekGeneratorTest(),
            new ShortenedDigestTest(),
            new EqualsHashCodeTest(),
            new TeaTest(),
            new XteaTest(),
            new Rfc3211WrapTest(),
            new SeedTest(),
            new NaccacheSternTest(),
            new Salsa20Test(),
            new XSalsa20Test(),
            new ChaChaTest(),
            new CMacTest(),
            new EaxTest(),
            new GcmTest(),
            new GMacTest(),
            new HCFamilyTest(),
            new HCFamilyVecTest(),
            new IsaacTest(),
            new NoekeonTest(),
            new VmpcKsa3Test(),
            new VmpcMacTest(),
            new VmpcTest(),
            new Srp6Test(),
            new SCryptTest(),
            new NullTest(),
            new SipHashTest(),
            new Poly1305Test(),
            new OcbTest(),
            new NonMemoableDigestTest(),
            new StreamCipherResetTest(),
            new SM3DigestTest(),
            new BCryptTest(),
            new OpenBsdBCryptTest(),
            new X931SignerTest(),
            new Blake2bDigestTest(),
            new Blake2sDigestTest(),
            new KeccakDigestTest(),
            new ShakeDigestTest(),
            new SM2EngineTest(),
            new SM2KeyExchangeTest(),
            new SM2SignerTest(),
            new SM4Test(),
            new X25519Test(),
            new X448Test(),
            new Ed25519Test(),
            new Ed448Test(),
        };

        public           void Main(string[] args)
        {
            foreach (ITest test in tests)
            {
                SimpleTest.RunTest(test);
            }
        }
    }
}