using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Tests
{
    [TestFixture]
    public class KdfCounterTest : SimpleTest
    {
        //private string kdfCtr = @"";


        [Test]
        public void TestCMAC_AES128_BEFORE_FIXED_8_BITS()
        {
            string name = "CMAC_AES128_BEFORE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("dff1e50ac0b69dc40f1051d46c2b069c"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("c16e6e02c5a3dcc8d78b9ac1306877761310455b4e41469951d9e6c2245a064b33fd8c3b01203a7824485bf0a64060c4648b707d2607935699316ea5");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("8be8f0869b3c0ba97b71863d1b9f7813");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES128_BEFORE_FIXED_16_BITS()
        {
            string name = "CMAC_AES128_BEFORE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("30ec5f6fa1def33cff008178c4454211"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("c95e7b1d4f2570259abfc05bb00730f0284c3bb9a61d07259848a1cb57c81d8a6c3382c500bf801dfc8f70726b082cf4c3fa34386c1e7bf0e5471438");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("00018fff9574994f5c4457f461c7a67e");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES128_BEFORE_FIXED_24_BITS()
        {
            string name = "CMAC_AES128_BEFORE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("ca1cf43e5ccd512cc719a2f9de41734c"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("e3884ac963196f02ddd09fc04c20c88b60faa775b5ef6feb1faf8c5e098b5210e2b4e45d62cc0bf907fd68022ee7b15631b5c8daf903d99642c5b831");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("1cb2b12326cc5ec1eba248167f0efd58");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES128_BEFORE_FIXED_32_BITS()
        {
            string name = "CMAC_AES128_BEFORE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("c10b152e8c97b77e18704e0f0bd38305"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("98cd4cbbbebe15d17dc86e6dbad800a2dcbd64f7c7ad0e78e9cf94ffdba89d03e97eadf6c4f7b806caf52aa38f09d0eb71d71f497bcc6906b48d36c4");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("26faf61908ad9ee881b8305c221db53f");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES128_AFTER_FIXED_8_BITS()
        {
            string name = "CMAC_AES128_AFTER_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("e61a51e1633e7d0de704dcebbd8f962f"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("5eef88f8cb188e63e08e23c957ee424a3345da88400c567548b57693931a847501f8e1bce1c37a09ef8c6e2ad553dd0f603b52cc6d4e4cbb76eb6c8f");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("63a5647d0fe69d21fc420b1a8ce34cc1");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES128_AFTER_FIXED_16_BITS()
        {
            string name = "CMAC_AES128_AFTER_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("b03616e032b6d1aa53352a8d7dfabcfe"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("fba6aea08c2ccf83f7142b72a476839a98a7d967125c9dfc83ae82f1fb6c913afc82bf65342356d2e7f929528589bc94c2f54d52b2487ee9f4a52510");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("8c5175addd7d847e30f48ef6ce373954");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES128_AFTER_FIXED_24_BITS()
        {
            string name = "CMAC_AES128_AFTER_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("03dd577bd0e65a26502453d5de9e682b"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("bf4e85e80ee83637bbe972a371c5a74d0511e0eeb9485f3d1d075f1fdbb00f5ea7f64b080cf2c8d21b213bb1e96cd047ddc3f005851bf4b07e7a0232");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("f8fa72a1f1c0b234c7f76a425778ad4e");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES128_AFTER_FIXED_32_BITS()
        {
            string name = "CMAC_AES128_AFTER_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("02f9ff0a7b136bdbdb09bc420a35d46f"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("ebdacfb0d14c6e38602dc95b43cea8d354596c360b31a02ea780d4fe35728ec75de2fb357c36c1210c10d35369982989ad02ab4f4094fdc86618e3f9");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("207ee3acb1d1785fb36109f9970153d8");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES128_MIDDLE_FIXED_8_BITS()
        {
            string name = "CMAC_AES128_MIDDLE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("b6e04abd1651f8794d4326f4c684e631"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("93612f7256c46a3d856d3e951e32dbf15fe11159d0b389ad38d603850fee6d18d22031435ed36ee20da76745fbea4b10fe1e");
                byte[] DataAfterCtrData = Hex.Decode("99322aae605a5f01e32b");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("dcb1db87a68762c6b3354779fa590bef");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES128_MIDDLE_FIXED_16_BITS()
        {
            string name = "CMAC_AES128_MIDDLE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("63cf79372dbe425d2c5832603fb96d93"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("91f5b0021524e8f85dc4af0bb83a9386e89635d19f9e4652d8d1837d2cdcd0b20fa50c1397ed450410cc9109b2ae1bad0b85");
                byte[] DataAfterCtrData = Hex.Decode("81205d2dc8429ce7e428");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("50569fc30e309a6337c14c5ba320271f");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES128_MIDDLE_FIXED_24_BITS()
        {
            string name = "CMAC_AES128_MIDDLE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("bc1b3659d7c2fcf008b0da456fd876c5"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("c8e13862185cbbee6544c2a7367d5216becf6352464b35e362c328f31b378f3481cdc09c46efed015dead1958db5701a940d");
                byte[] DataAfterCtrData = Hex.Decode("a75853711d59f7b819b0");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("da6a63b32c2f051e9833d61f92f35d70");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES128_MIDDLE_FIXED_32_BITS()
        {
            string name = "CMAC_AES128_MIDDLE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("90e33a1e76adedcabd2214326be71abf"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("3d2f38c571575807eecd0ec9e3fd860fb605f0b17139ce01904abba7ae688a50e620341787f69f00b872343f42b18c979f6f");
                byte[] DataAfterCtrData = Hex.Decode("8885034123cb45e27440");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("9e2156cd13e079c1e6c6379f9a55f433");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES192_BEFORE_FIXED_8_BITS()
        {
            string name = "CMAC_AES192_BEFORE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("53d1705caab7b06886e2dbb53eea349aa7419a034e2d92b9"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("b120f7ce30235784664deae3c40723ca0539b4521b9aece43501366cc5df1d9ea163c602702d0974665277c8a7f6a057733d66f928eb7548cf43e374");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("eae32661a323f6d06d0116bb739bd76a");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES192_BEFORE_FIXED_16_BITS()
        {
            string name = "CMAC_AES192_BEFORE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("d7e8eefc503a39e70d931f16645958ad06fb789f0cbc518b"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("b10ea2d67904a8b3b7ce5eef7d9ee49768e8deb3506ee74a2ad8dd8661146fde74137a8f6dfc69a370945d15335e0d6403fa029da19d34140c7e3da0");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("95278b8883852f6676c587507b0aa162");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES192_BEFORE_FIXED_24_BITS()
        {
            string name = "CMAC_AES192_BEFORE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("f7c1e0682a12f1f17d23dc8af5c463b8aa28f87ed82fad22"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("890ec4966a8ac3fd635bd264a4c726c87341611c6e282766b7ffe621080d0c00ac9cf8e2784a80166303505f820b2a309e9c3a463d2e3fd4814e3af5");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("a71b0cbe30331fdbb63f8d51249ae50b");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES192_BEFORE_FIXED_32_BITS()
        {
            string name = "CMAC_AES192_BEFORE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("f4267280cb8667c2cf82bb37f389da6391f58cc74deba0cc"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("34abbc9f7b12622309a827de5abfdd51fb5bb824838fcde88ca7bc5f3953abdcb445147f13e809e294f75e6d4e3f13b66e47f2dfc881ed392e3a1bf6");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("2d1b4b5694b6741b2ed9c02c05474225");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES192_AFTER_FIXED_8_BITS()
        {
            string name = "CMAC_AES192_AFTER_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("aea3dd304d0475e7969d0f278d23abe1fc0c7220f7fd7e73"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("3e6008930b20b14375f86176714558113284d4142806d9d810b3fe4c02ae375f2b7e6ec05fb15fcd8da82b90c9706cf36b2c9dd96a2c1f46606f6bde");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("12c6f91ead9b6f256e97b17efc8928d1");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES192_AFTER_FIXED_16_BITS()
        {
            string name = "CMAC_AES192_AFTER_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("ff8902c49d5acf676a9fd0c435a0d340d19622690bf16993"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("4820bac046633e0354dbfba484c60e8a48ee839639484b173fb34c84dd2b94a7a8102f9a9f493656958bfdbe59956963594164c4518a375b87ce9c36");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("bafb45bc485bcad6236577e3fadebab6");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES192_AFTER_FIXED_24_BITS()
        {
            string name = "CMAC_AES192_AFTER_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("b880d5bbadd02b32af31b5d69bd5a2da2654f93e85474d64"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("b8434bbf8353167fddb5fef6deb65239cb9db201e7e3cc1a8253b999f80ee04cfcefef3bce8fc4b0afb263d4515c794306cb0300cc07a1b7dce2b341");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("f0f932dd19d194193b9f93e43ae59324");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES192_AFTER_FIXED_32_BITS()
        {
            string name = "CMAC_AES192_AFTER_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("f3bb6d3d0a20c8256fa3ef7586b77dd950ccc1221f07ca82"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("edd3964cdd146f8de1b160565c252c6b513bd3f4be07357ddae662e6b4683fbfa41b6a7df87ceced255051e3713f958305bc822beb96c5aeb4f7af7c");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("073d40c5626931f27c5556d9f1d1ba7a");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES192_MIDDLE_FIXED_8_BITS()
        {
            string name = "CMAC_AES192_MIDDLE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("e09079196120accdf43293f3593e692481391080e233f40b"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("0ec4fb9f0b4c59bbcbbf2c85466f92e1631cac32827e0485b6c56ba2ba5e72252f3c0895fd48ffbe18735d5c8d9a15c3985f");
                byte[] DataAfterCtrData = Hex.Decode("9a1a87dfa1698b60d0a0");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("2233d0566417bb549d3d5e9e28673168");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES192_MIDDLE_FIXED_16_BITS()
        {
            string name = "CMAC_AES192_MIDDLE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("60efefde5ac9d43b097b809752e7fc4c21181300101ee03b"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("34a86821dee0fdbfd8aef3f7cf86184e7f669c505c3cb4c88f92e9ca514549c334cdc079bfe075338ba21fe0847c7e29a7df");
                byte[] DataAfterCtrData = Hex.Decode("d8d290cebb39941de12b");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("75304faf483287177b71adbbaae7dfa3");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES192_MIDDLE_FIXED_24_BITS()
        {
            string name = "CMAC_AES192_MIDDLE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("60c8df63954f410af68f1bde52fdd3432d6baf7079a4c795"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("b1907a06c3428b4e4656672742b0d933773cab80bd6678c2f897339e59fbe790f4391a96d18ca19522d64f4a2e852848c6af");
                byte[] DataAfterCtrData = Hex.Decode("781103fc1a702a561ced");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("e69ac242bb5d0dd4da3c2f219f061cd6");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES192_MIDDLE_FIXED_32_BITS()
        {
            string name = "CMAC_AES192_MIDDLE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("bdb7b0516fca692f5532667c2b34456de348afe6c1e43ad1"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("6d5fd4790cc1d2b85bdb42e33df3debaeea4dc8ef6868482aa49562e3504f8511111898baa2e63a1e932cb83eb2799d23788");
                byte[] DataAfterCtrData = Hex.Decode("0bfa079f2f0aeb334ebf");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("556adac744b1513b50515a6df6bb983e");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES256_BEFORE_FIXED_8_BITS()
        {
            string name = "CMAC_AES256_BEFORE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("aeb7201d055f754212b3e497bd0b25789a49e51da9f363df414a0f80e6f4e42c"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("11ec30761780d4c44acb1f26ca1eb770f87c0e74505e15b7e456b019ce0c38103c4d14afa1de71d340db51410596627512cf199fffa20ef8c5f4841e");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("2a9e2fe078bd4f5d3076d14d46f39fb2");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES256_BEFORE_FIXED_16_BITS()
        {
            string name = "CMAC_AES256_BEFORE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("4df60800bf8e2f6055c5ad6be43ee3deb54e2a445bc88a576e111b9f7f66756f"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("962adcaf12764c87dad298dbd9ae234b1ff37fed24baee0649562d466a80c0dcf0a65f04fe5b477fd00db6767199fa4d1b26c68158c8e656e740ab4d");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("eca99d4894cdda31fe355b82059a845c");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES256_BEFORE_FIXED_24_BITS()
        {
            string name = "CMAC_AES256_BEFORE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("1612a40daa7fce6c6788b3b71311188ffb850613fd81d0e87a891831348e2f28"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("1696438fcdf9a85284759b2604b64d7ea76199514709e711ecde5a505b5f27ae38d154aba14322481ddc9fd9169364b991460a0c9a05c7fcb2d099c9");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("d101f4f2b5e239bae881cb488995bd52");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES256_BEFORE_FIXED_32_BITS()
        {
            string name = "CMAC_AES256_BEFORE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("d0b1b3b70b2393c48ca05159e7e28cbeadea93f28a7cdae964e5136070c45d5c"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("dd2f151a3f173492a6fbbb602189d51ddf8ef79fc8e96b8fcbe6dabe73a35b48104f9dff2d63d48786d2b3af177091d646a9efae005bdfacb61a1214");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("8c449fb474d1c1d4d2a33827103b656a");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES256_AFTER_FIXED_8_BITS()
        {
            string name = "CMAC_AES256_AFTER_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("d22779384558d1ae649896e8d844f29a4ff3dfc1a9fbb7c34e20738f8c795e17"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("498cf66c5fd3578ff574ed8c85d072dcd9e18e4f07b0aaecad785c9058fa0f17647673df807984f5f20dec47e699aebd882e485a8afc44c4bc680d07");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("c721f54afaa0e31886df39bf405514d1");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES256_AFTER_FIXED_16_BITS()
        {
            string name = "CMAC_AES256_AFTER_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("6205ae02dc1e943506ac7049889de1d9e4cfb7e696508ec999f4cb3d06ac5964"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("b145c7c120101f418f069dd639feda41c36ffc64a251afb5829c4c71572f16a5cdbf8518d8b9fad7a7ef40483ad0f8a8c044aefb7dc8b465923ab403");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("22001c6de7ca7e303cfa7266f834d7fc");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES256_AFTER_FIXED_24_BITS()
        {
            string name = "CMAC_AES256_AFTER_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("404b2b964f2cc8f50b614f591a58d15c21844c115d8b62472f06bdd82a992a5e"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("bdbe08a73cae7a5f6ce100753b981d4fc432da7cd841095a211b60f3c7b0a6297d98b84246cf9fe62bd02022c7b50e88a5cafc400aa881cadc5f8979");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("897f6aebf46fb0ee41a89b324ee82edd");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES256_AFTER_FIXED_32_BITS()
        {
            string name = "CMAC_AES256_AFTER_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("746c44c4129858d89e50e09dc44aec2ab2158c2e0c6bb73b35588e94e33a1958"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("ebeed6a0462577b6b4e2fe4697c6ae6e1c6b8b9fd14381247bc2cf2c06d7afb55b06389612a85d0a69a1486eb399e7f314b234fd44908396b55f6e67");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("85e1cd8cea5a43f7f5b626fa7666f550");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES256_MIDDLE_FIXED_8_BITS()
        {
            string name = "CMAC_AES256_MIDDLE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("701c0f5a65a42d07077d6eedf540ef9374bcb74cb89bfe017e5ca1e9df6b2b70"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("2ce10feb56dda9fdc95da5b5013f05f59d13a89b3a1ad4527bd00612190ac6613b007afdf00fbc920cc6e8d5fd9da9ae267d");
                byte[] DataAfterCtrData = Hex.Decode("86373a67ab86e7bde5b7");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("0ca10ea17fd28eaf660191fd983cb353");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES256_MIDDLE_FIXED_16_BITS()
        {
            string name = "CMAC_AES256_MIDDLE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("ce7ec625c6dcd1ff21ec48ed35ff70fc0f69946107e6583849f711a725ba1684"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("14e20e83dbe001af8ab304d0cf14dba30caa751271b976a927b3c8544e24ad0a98e6604eddd9fda2bf2a9ba81ec507f942f5");
                byte[] DataAfterCtrData = Hex.Decode("43a412a8be794adb0f2e");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("e2c310966e6cf312eff7ab44deddb9dc");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES256_MIDDLE_FIXED_24_BITS()
        {
            string name = "CMAC_AES256_MIDDLE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("bcc9da67e6309c4c365de53a040fa6a64f387d48257fd1751cffdfae6644c59a"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("6740b398eff3ec6288090caac3ae9210c91809774172e108bb51a216eaa5a67cd0420932146a42254d3e2b8c2c34f9c118ed");
                byte[] DataAfterCtrData = Hex.Decode("335747e149d25dccf1ff");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("0288ef588897480caeb1d0d9cd30a6d9");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_AES256_MIDDLE_FIXED_32_BITS()
        {
            string name = "CMAC_AES256_MIDDLE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("04618a8e172eb80eef23e5b95c736acf6b7aac16b9fdbdae1ef73d777380bb49"); IBlockCipher blockCipher = new AesEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("4cca08a93ba374efbf69cad9601f3782089eb5aeb128a59a8c1f687bee5eba8c56bdb1354e1eb945542df52441667502c82a");
                byte[] DataAfterCtrData = Hex.Decode("fedd474f5dc3033fa3ca");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("bd4299f66136975d87f65b5eda112710");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES2_BEFORE_FIXED_8_BITS()
        {
            string name = "CMAC_TDES2_BEFORE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("b9414ff3788ce4e1a7db5046a012dd9c"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("346df581169dd40d11908314fa23e0ee18befd00151f8c8937ad4f978600c3a6fa8a2162aeafce11e593aaf607094778b872e083e9e3549a05cae069");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("f83dde63c47cdb30d7ad357d08c5de98");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES2_BEFORE_FIXED_16_BITS()
        {
            string name = "CMAC_TDES2_BEFORE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("52a865ecdc1bc07b7d42efa8b9c8751f"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("626e5f408274be0c0661415affe5dd9a0e5907740b106a5fc45b02dd2393d699d393e32cd29bfe2faa849f1bda756d9defae6654bfd8ee20af38fe34");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("09afb33650e00bbe6a485d6f4004dedd");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES2_BEFORE_FIXED_24_BITS()
        {
            string name = "CMAC_TDES2_BEFORE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("591f8097bee804e1089105acda371a59"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("dd610f376e588224e616e15533f4e14696f6bb31528c6b6a835e26a0a7986a32c791db165538a0cdece935f7e1459579dc59ff3b80dc187f93b85864");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("b47b488ad6ec7ee5a21f77cdf8b805a4");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES2_BEFORE_FIXED_32_BITS()
        {
            string name = "CMAC_TDES2_BEFORE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("0cd1600ab3357416515adf83c39916e9"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("163b94f161d9219a151c13ec74391a7d10183a78ddcf09805e2d637a5a658c2491c2a81e3c208bf46827565a10ac81caa5cbffebb76d23c7fd4261d0");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("ad197bd9913694c5a5f1230cf8720955");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES2_AFTER_FIXED_8_BITS()
        {
            string name = "CMAC_TDES2_AFTER_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("f1adfb9fd1740d2deb7002be11064f2a"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("7c88743991919940f5bf56bc2db728b192e03a1ba51661a1621585168b9a6c898f898ea4da37da8bc983d37acba01a2fe1599e24128a98c3141e790e");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("03893271c38d43058a6bc85cc3b98fd9");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES2_AFTER_FIXED_16_BITS()
        {
            string name = "CMAC_TDES2_AFTER_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("12dde64a6eb639f5d3008ab1e866d6bc"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("310008b5ad01f6c1df3d64a204017f449b722cada2b8d018a67adeb92a067d8f57b4611363eda7783faf0f7c6b1ef5c1b93c69456041c671290a3929");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("0602f936e1883c6b38ff4e34abf455e6");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES2_AFTER_FIXED_24_BITS()
        {
            string name = "CMAC_TDES2_AFTER_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("4b0ec2cfffc01d9af6e622f78cc143f5"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("db2529059882038b28cdbc8a1971d78be996fe26515af88a83c833726081a1523c801aec63b115b5f9fc8e67bea30a7aaeb1aceabcb4924ab7fcecff");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("983ad3eaa545c9bb1df934912fc812c7");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES2_AFTER_FIXED_32_BITS()
        {
            string name = "CMAC_TDES2_AFTER_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("35261d795e6b35abf7631f39d9358655"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("29dcfcf5c8fef254fa2d3b388b5a8b0e4b2eeb820264933e0bf0c148645c8cca98388a93768735a4c09c94e90121e65f1a16269c64e5b9301b049762");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("b16fc1cfe3e1437e374909443777c244");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES2_MIDDLE_FIXED_8_BITS()
        {
            string name = "CMAC_TDES2_MIDDLE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("9b7472291bbe27db6fab01fde89a09af"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("6c4e11221aec7ce087ba1456adbadb62cc72ccf3673912350e8d1632f9b90997b270b7803bbeccaa8b0349be34edfa49b633");
                byte[] DataAfterCtrData = Hex.Decode("91353a575c9f71780202");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("beeef41b4671715f28419ed6aa6c8a98");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES2_MIDDLE_FIXED_16_BITS()
        {
            string name = "CMAC_TDES2_MIDDLE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("28908f47deb831129e9cca49e8cd4a4a"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("c8876e7259e1291aa032f442b87daa555b64cc7dde1bafd0e5b1824b2e35dad21fac7231f7e248c1b412d5bc0da259cf6793");
                byte[] DataAfterCtrData = Hex.Decode("2dee3c7b9a9b8b99325a");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("1258667e41849300d28f8d7fda88d073");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES2_MIDDLE_FIXED_24_BITS()
        {
            string name = "CMAC_TDES2_MIDDLE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("b1b415150a302d75d4d0787693491067"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("2da644277d9a9bdc9b71c527bb326bb0ecd9a79c5612545a10351565a0b7709158b8a5692ab3cd0b396b575a796388e50bad");
                byte[] DataAfterCtrData = Hex.Decode("79a3ede12b55c7a03098");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("a4c76b2240aaf6528a2c595137495e08");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES2_MIDDLE_FIXED_32_BITS()
        {
            string name = "CMAC_TDES2_MIDDLE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("3363baa77afae6b2392959f759058ff2"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("3ad9c61856c8dbe27c8872e71c961e9ff048d7417f820cb0e91e4b84ec793900617dedfee369bb8a5a0e0ae2a0eb73ede4c0");
                byte[] DataAfterCtrData = Hex.Decode("7905ffa7520728c16975");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("39431682b1a75ad6a7e22a78c631b1b6");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES3_BEFORE_FIXED_8_BITS()
        {
            string name = "CMAC_TDES3_BEFORE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("89b3469ce73b4fef33244de2cb772bc239a4261a45993b3b"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("f1aec104bc3b1735e28f90a6d3aa7cd319841303989bc4a2a0da886c5c5764d0bd7c12d94723133f664a109d289d0f2971cbfec4da2f3b5cbfbc47f2");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("af52a719396e6eecc4cb323994113f42");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES3_BEFORE_FIXED_16_BITS()
        {
            string name = "CMAC_TDES3_BEFORE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("59850d301cc30ded3c9a78181ec7f466743c06ea1294f84b"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("1a8011295716fd54dd8d87bd8f3b27e296c03997e427836ae5a79ac3989a3b769b2ab5d5bb560a58e8cb996a34b2c0f8439ff8b1517b783d85a51b0c");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("ac7420b7b315ad0482f1d8f78bb26867");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES3_BEFORE_FIXED_24_BITS()
        {
            string name = "CMAC_TDES3_BEFORE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("a36813220b356493d6414e506e902c225a12190a353bf326"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("0d48409241aa1346b4f3576c88a720e0de04ec23973f2f5c0a1f083c50aed3198ced13bb521233dd94d6748c2dd184100489c808a143a4cf6be5f30b");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("27626c6d07ff4c13cc596c9ff57425c0");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES3_BEFORE_FIXED_32_BITS()
        {
            string name = "CMAC_TDES3_BEFORE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("a1440ebcdfe3eb349b3394938bc4c3f0f52bffb15ed0a20c"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("ac8ce20d7fa0a07e6351cb0435c8e762aee6394f870108c66bbe6d75a1a8079bb2f778b4f896d8a739000731784618086b0fbfa25453c69b8dc2cafd");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("3b924d2d2101544ac09d2abe9a258059");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES3_AFTER_FIXED_8_BITS()
        {
            string name = "CMAC_TDES3_AFTER_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("7e3c2b8dcb802b4f504865711e7e8fdfa2f4025a5422d165"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("c45b6d6123dade0d8c670764bb1a0e89a4bd968e87332776421e43ccb7f542653305eae98d74fda39800f11e7b29723613f5a55fb5fdfbe6df9a97d9");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("9284f48d951df2275f1a19985029e992");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES3_AFTER_FIXED_16_BITS()
        {
            string name = "CMAC_TDES3_AFTER_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("38e68dc86bc2f071b022447760f05d58d228c61161c6150b"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("06ae7937f05880e4d3975b29bc6f6a2497badb4adbe218c8c43815598c06e9cefbd02abb07e050215614e215bc5424921e702ec6d691ccbebea925fa");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("c78dc22844e8ec864c7aeaec3b915f0c");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES3_AFTER_FIXED_24_BITS()
        {
            string name = "CMAC_TDES3_AFTER_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("6b3e828fedf4c09a5c12add793fe93dceebf4d73dd8aac7d"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("21f099f2d815a165780660880eabc61a3086e4671270b7ba7e357dd0b7a02348fd65c911fab319d0696cd6f208066690c1b9f240036f20e0d4ab541f");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("60b0c85b67a8369ff837186b9df66c30");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES3_AFTER_FIXED_32_BITS()
        {
            string name = "CMAC_TDES3_AFTER_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("93e6c8cd13f94cf7261b3d1aae32236484af0c9deb10e706"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("d466b528b7feb554c81059f2856170cc036007792ff6f4503e36bc8a4c95ce243600653373dafc25a163f301eef3d074ee827bd5a2e36ee2b5d46328");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("4c846ebe416463bd85e68013a65212c6");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES3_MIDDLE_FIXED_8_BITS()
        {
            string name = "CMAC_TDES3_MIDDLE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("acdcf0400857f9e500314327ecceed5a5524670f3a4db8fd"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("d10bfe3b052cc940542aa92026ee0d8c3d1836e52147ffbc8521e1a0812a17e99b966e4dbe2a746a6fcaddec9236dabfd9ed");
                byte[] DataAfterCtrData = Hex.Decode("b15b26e785ddb21056fa");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("d7815ac538a9674eabf41f4077b1355a");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES3_MIDDLE_FIXED_16_BITS()
        {
            string name = "CMAC_TDES3_MIDDLE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("9b9c7898dc438b12b103fcaf6e80586c7c1d8b9ded1bddbe"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("62efc3670c8f74b590a6779a637b3e3204bfce94e42b4e8d276d2106b29ac90951635b7b526451b87b99feb13db517bc4567");
                byte[] DataAfterCtrData = Hex.Decode("5a7d10e548f03b474b90");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("d717ef6b042fc14bdd3f37049c1c8a8c");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES3_MIDDLE_FIXED_24_BITS()
        {
            string name = "CMAC_TDES3_MIDDLE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("9bc139be964cce8ef17205870faeea3329c219a300fb4db4"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("a4b7a50a70c89c8e46c3d15da45b62e23ee9af2f5862c18ac56f2523d2853f5cbc0c26733c496e3a80f87024774bbd54ee16");
                byte[] DataAfterCtrData = Hex.Decode("d6de2ce1910de7eb033c");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("7b21d229d24201d25b66c234ed333072");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestCMAC_TDES3_MIDDLE_FIXED_32_BITS()
        {
            string name = "CMAC_TDES3_MIDDLE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("7ba45fbfa4b8aef5b6c0a193f8041440388f3c24479eb8f9"); IBlockCipher blockCipher = new DesEdeEngine();
                IMac prf = new CMac(blockCipher); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("ac83b0bf7beba95fc4442755ef77e8e4a6dc03f5c861295b9fc71fb5fcaa5aba73048ac89771dacfc34c5e332d7f4b419c49");
                byte[] DataAfterCtrData = Hex.Decode("980cfefbf2dd602ddfca");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("9cfb77a4f4af262a9ae707abe2913cd6");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA1_BEFORE_FIXED_8_BITS()
        {
            string name = "HMAC_SHA1_BEFORE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("00a39bd547fb88b2d98727cf64c195c61e1cad6c"); IDigest digest = new Sha1Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("98132c1ffaf59ae5cbc0a3133d84c551bb97e0c75ecaddfc30056f6876f59803009bffc7d75c4ed46f40b8f80426750d15bc1ddb14ac5dcb69a68242");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("0611e1903609b47ad7a5fc2c82e47702");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA1_BEFORE_FIXED_16_BITS()
        {
            string name = "HMAC_SHA1_BEFORE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("a510fe5ad1640d345a6dbba65d629c2a2fedd1ae"); IDigest digest = new Sha1Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("9953de43418a85aa8db2278a1e380e83fb1e47744d902e8f0d1b3053f185bbcc734d12f219576e75477d7f7b799b7afed1a4847730be8fd2ef3f342e");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("c00707a18c57acdb84f17ef05a322da2");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA1_BEFORE_FIXED_24_BITS()
        {
            string name = "HMAC_SHA1_BEFORE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("928c170199473291bf719a1985a13673afb8f298"); IDigest digest = new Sha1Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("f54388503cde2bf544db4c9510ff7a2759ba9b4e66da3baf41c90ce796d5ea7045bc27424afb03e137abfafe95158954c832090abdba02d86bab569d");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("8c01160c72c925178d616a5c953df0a7");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA1_BEFORE_FIXED_32_BITS()
        {
            string name = "HMAC_SHA1_BEFORE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("f7591733c856593565130975351954d0155abf3c"); IDigest digest = new Sha1Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("8e347ef55d5f5e99eab6de706b51de7ce004f3882889e259ff4e5cff102167a5a4bd711578d4ce17dd9abe56e51c1f2df950e2fc812ec1b217ca08d6");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("34fe44b0d8c41b93f5fa64fb96f00e5b");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA1_AFTER_FIXED_8_BITS()
        {
            string name = "HMAC_SHA1_AFTER_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("7184596b9489c763b8399b3350e60929965a961c"); IDigest digest = new Sha1Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("cd9e9f2b263f7b02eceadd0b532efa971ec28c77b1dbaf23e90e0a85360048ed8d3debbeb224060da0b4bf1e85da2a6ee122253b9e93784ccae35c77");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("21816e8213fff01e9a9c29e93c6a0b17");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA1_AFTER_FIXED_16_BITS()
        {
            string name = "HMAC_SHA1_AFTER_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("87cb4849bfd2d206c09f6aea565207a733dde270"); IDigest digest = new Sha1Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("d1c928a1872febfa53813b7ae057840ecf38f9cd684609a7941a14b4fdfb9dd3fa45aa43854496b73778ec504cb2ffb3b75e6d06d0d7a452e3cc7716");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("3fdf6a4a85c9b41c35400521168a243e");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA1_AFTER_FIXED_24_BITS()
        {
            string name = "HMAC_SHA1_AFTER_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("af9b01a7b62880584dc30904fc4ee34af814bda4"); IDigest digest = new Sha1Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("61715afc4a0ff01c136f97f0768edc621a710da6abb127340ea92f558751117e31ea444f39abe0ba267a4a4039e67ef39e6823fd830db17c04d69cb0");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("33336e8a1f75ec8116832776d9bad9aa");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA1_AFTER_FIXED_32_BITS()
        {
            string name = "HMAC_SHA1_AFTER_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("bc8ac288eea767df58a425a34412ccaa1444f40b"); IDigest digest = new Sha1Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("c593baf7d414650b8e5895acf00c4e1ce1412cf2eebb890dbc8369d8bc483a345419c97db45cf5a8b114ae9c87a7beb7a97ee2acdb54e7e741cfaa03");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("5a130ef26a2bf93b15e3df244a72db10");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA1_MIDDLE_FIXED_8_BITS()
        {
            string name = "HMAC_SHA1_MIDDLE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("f3f5dfa9be304476e633ccaec4f988013600e415"); IDigest digest = new Sha1Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("f9de4cf03c3f15cff003e9bad5de4d16eb791417072e1d8fe0375ad434536fcc95bf7eb3ba1704a4899d80946060c4f094f8");
                byte[] DataAfterCtrData = Hex.Decode("fd7a95a129f48ca7a937");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("0de4ce13a4114687526ecb0f53607867");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA1_MIDDLE_FIXED_16_BITS()
        {
            string name = "HMAC_SHA1_MIDDLE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("6d85df76f0a7bb8ce5df4f14ebbc77a0037dc327"); IDigest digest = new Sha1Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("bb5f3f1a0aab0c239350943880e6d19698655dc95fe9778e07d007f72924311267a5c3e1c95ad9b0f1b9731be098b453f7ba");
                byte[] DataAfterCtrData = Hex.Decode("88295a9d15d0a5294219");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("8c088ed7c6bbef7d9e7c55e07b7b0ce5");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA1_MIDDLE_FIXED_24_BITS()
        {
            string name = "HMAC_SHA1_MIDDLE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("00fbfbfd14d5aea6d837e2c05f2bca244e04e578"); IDigest digest = new Sha1Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("72a9d1693cd99c5bf82475b843859919a7c3b30f2243986a90b1ce790a67831446cc929402256408f910ce6c468ee04f8ebe");
                byte[] DataAfterCtrData = Hex.Decode("5a9b64aafb7c7cacb483");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("a29ff62f059e3a23ce00f0983f998bb2");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA1_MIDDLE_FIXED_32_BITS()
        {
            string name = "HMAC_SHA1_MIDDLE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("4e8ec7f7d4b1595f62d400d02e2e8b7634cc5f41"); IDigest digest = new Sha1Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("46fc844d9b22f21fd4f033a180a6e7a0fe5b2fe2675bb64ac1c84eb31fa56aebab35d8e907f291a868d76322c1b01468f9dc");
                byte[] DataAfterCtrData = Hex.Decode("96712d4ad2011956403a");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("eac2623b46e3abc112a70cac89499744");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA224_BEFORE_FIXED_8_BITS()
        {
            string name = "HMAC_SHA224_BEFORE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("7e2f7a5ab3e82ef927a005308456823da473787bf33d18a864aca63f"); IDigest digest = new Sha224Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("b35695a6e23a765105b87756468d442a53a60cd4225186dc94221c06c5d6f1e98462135656ebca90468a939f29112b811413567d498df9867914d94c");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("10ba5c6ea609da8fa8abe8be552c97a1");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA224_BEFORE_FIXED_16_BITS()
        {
            string name = "HMAC_SHA224_BEFORE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("093b2ce84c6175d1723fbe94b9ee963b6251d018fcf8c05c2e3e9b0b"); IDigest digest = new Sha224Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("083e114aca1f97166551b03f27b135c0c802294aa4845a46170b26ec0549cb59c70a85557a3fc3a37d23eed6947d50f10c15baf5c52a7b918ca80bf5");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("94ced61c3665616d4a368f83a7283648");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA224_BEFORE_FIXED_24_BITS()
        {
            string name = "HMAC_SHA224_BEFORE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("f09e65e8de7500847b43bd95e6c3506e01aadd484e9699b027897542"); IDigest digest = new Sha224Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("c20f6188517b2ca10086b9f7f8d6f2d38d66f24193c037008d035f361c6bd74db26aef588a87aa8a1c3cdad2ba0207f7e7b39def0df797c4cb3bf614");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("73d30c2af54744eb1efb70429f8e303a");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA224_BEFORE_FIXED_32_BITS()
        {
            string name = "HMAC_SHA224_BEFORE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("f5cb7cc6207f5920dd60155ddb68c3fbbdf5104365305d2c1abcd311"); IDigest digest = new Sha224Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("4e5ac7539803da89581ee088c7d10235a10536360054b72b8e9f18f77c25af01019b290656b60428024ce01fccf49022d831941407e6bd27ff9e2d28");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("0adbaab43edd532b560a322c84ac540e");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA224_AFTER_FIXED_8_BITS()
        {
            string name = "HMAC_SHA224_AFTER_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("ab56556b107a3a79fe084df0f1bb3ad049a6cc1490f20da4b3df282c"); IDigest digest = new Sha224Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("7f50fc1f77c3ac752443154c1577d3c47b86fccffe82ff43aa1b91eeb5730d7e9e6aab78374d854aecb7143faba6b1eb90d3d9e7a2f6d78dd9a6c4a7");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("b8894c6133a46701909b5c8a84322dec");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA224_AFTER_FIXED_16_BITS()
        {
            string name = "HMAC_SHA224_AFTER_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("473905e06f47138e9a4e3b8bdd5ae10dface4ba8f6dd16b142c38e14"); IDigest digest = new Sha224Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("4bf2e149227498945b061db33cd4695eb88d1d47b05b344cc01105df91136732eaa3c60f3e0c97a81a00148e390d37f000a6de6f15adfdc676911ae7");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("125f1ddd2f36cb3262fdc9413fbf88c3");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA224_AFTER_FIXED_24_BITS()
        {
            string name = "HMAC_SHA224_AFTER_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("4435e0203ca73e356595d8c237b549463055b27dc259ef1f31a57e3d"); IDigest digest = new Sha224Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("d486f6a5c54f88b6104d078791489d7c1c768bca7ef9f61571fc9a6daeb0acfd113d8623b84d3af98fa732517d3a18aa04c2174592cc261875883df2");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("dc0bbe8781137001eed5925bfc6d8321");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA224_AFTER_FIXED_32_BITS()
        {
            string name = "HMAC_SHA224_AFTER_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("a31c0ed2aedb5fb260d1307d33db883f681d3efd300efcfd8fe306d7"); IDigest digest = new Sha224Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("43ebd9bc28ac01d90b86eccfff188113d1d4703f9f56762206e6d90747c3d20f7ea130727893db5fb6cf18cb59c62bd02599fd3e6403d55139cf862a");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("4cab02879876d630b6f8aee1c32253ca");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA224_MIDDLE_FIXED_8_BITS()
        {
            string name = "HMAC_SHA224_MIDDLE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("92edfe9fddd85a3d13f183f57988d45d459657fee0d31679a6a2c293"); IDigest digest = new Sha224Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("598b5733a34c47c2b8c91ce4e6d588eaa3d874a20f430a9748970e499f3ca3d671f038986e084ff9dc1d308728276581864f");
                byte[] DataAfterCtrData = Hex.Decode("4b1aea8ab1bd24b56527");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("9d68a6108f912bd823025dfb5441ca3f");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA224_MIDDLE_FIXED_16_BITS()
        {
            string name = "HMAC_SHA224_MIDDLE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("7078b224ee6867f43ac3d2d555bb2dfc935fca44faec5f88124f6e1d"); IDigest digest = new Sha224Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("b9466561ff1bc6d2058bbe708e695601196fda17978188e6264cd57e1fc298f554bb769699c49a825d6e278206f6614cbbae");
                byte[] DataAfterCtrData = Hex.Decode("6f4792fc8bc75a003773");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("4b81681a8c56d5d6aa2f4d44cae06693");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA224_MIDDLE_FIXED_24_BITS()
        {
            string name = "HMAC_SHA224_MIDDLE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("8d6af06e28ef54e21463f86cd02335e7efff7cb21215dd05537b8dd6"); IDigest digest = new Sha224Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("acf7fdce77544ce24d135c5040a4ac6ceb38ab7a4e526ac4aef3f2b2d670bf045dac9e5380ef32d4d6b72561797e11fa3e7b");
                byte[] DataAfterCtrData = Hex.Decode("ac233ffa791c96b42569");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("4261c3e8e28e2dc518f0a048572d8bbe");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA224_MIDDLE_FIXED_32_BITS()
        {
            string name = "HMAC_SHA224_MIDDLE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("497bb6b1ff3c1d1bbd14a69dd7ccfa500ab9fc60849ce8083a1b2d58"); IDigest digest = new Sha224Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("193819c01c6d73a629ef71d8159e22aa635c7e7c96ceb8b7b4867be2a8f518139c2c678eefd15c9957ad261bd27a78745881");
                byte[] DataAfterCtrData = Hex.Decode("1731446c3dc54a4ae669");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("9a5a67b2dbf4ade2bc6864da5efd2b56");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA256_BEFORE_FIXED_8_BITS()
        {
            string name = "HMAC_SHA256_BEFORE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("3edc6b5b8f7aadbd713732b482b8f979286e1ea3b8f8f99c30c884cfe3349b83"); IDigest digest = new Sha256Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("98e9988bb4cc8b34d7922e1c68ad692ba2a1d9ae15149571675f17a77ad49e80c8d2a85e831a26445b1f0ff44d7084a17206b4896c8112daad18605a");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("6c037652990674a07844732d0ad985f9");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA256_BEFORE_FIXED_16_BITS()
        {
            string name = "HMAC_SHA256_BEFORE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("743434c930fe923c350ec202bef28b768cd6062cf233324e21a86c31f9406583"); IDigest digest = new Sha256Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("9bdb8a454bd55ab30ced3fd420fde6d946252c875bfe986ed34927c7f7f0b106dab9cc85b4c702804965eb24c37ad883a8f695587a7b6094d3335bbc");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("19c8a56db1d2a9afb793dc96fbde4c31");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA256_BEFORE_FIXED_24_BITS()
        {
            string name = "HMAC_SHA256_BEFORE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("388e93e0273e62f086f52f6f5369d9e4626d143dce3b6afc7caf2c6e7344276b"); IDigest digest = new Sha256Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("697bb34b3fbe6853864cac3e1bc6c8c44a4335565479403d949fcbb5e2c1795f9a3849df743389d1a99fe75ef566e6227c591104122a6477dd8e8c8e");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("d697442b3dd51f96cae949586357b9a6");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA256_BEFORE_FIXED_32_BITS()
        {
            string name = "HMAC_SHA256_BEFORE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0"); IDigest digest = new Sha256Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("10621342bfb0fd40046c0e29f2cfdbf0");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA256_AFTER_FIXED_8_BITS()
        {
            string name = "HMAC_SHA256_AFTER_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("08d0a37d2e2fb84d44838efaeac28135d964b0daf154369783cfe007fa883966"); IDigest digest = new Sha256Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("80866d761e34084b45ea668a25deabffdbca446aa0bf793bccdf3790d584d26056315a4c060ac7b1b01cace96ba97e8fed81953c8b82ba5132dd1713");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("8f5b47d23d5d3ba632acdf6543509bd8");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA256_AFTER_FIXED_16_BITS()
        {
            string name = "HMAC_SHA256_AFTER_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("3b11d0b6f1b49d1a41eecc7448766bbfee47d32a28a3f2be3d3b5f21c4d1e6c6"); IDigest digest = new Sha256Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("a6aca3725e8687268cd9cefcc4f3799090568e777a18e82569922463658c4e8fce319316edc172eae3c7e4f4224ffe7d72730ec2f8472f80122a5cc0");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("fffbde92bad6dbfc61953b78c47f7b93");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA256_AFTER_FIXED_24_BITS()
        {
            string name = "HMAC_SHA256_AFTER_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("585245d11e0b69d10e2ea39c76c8625003aa775037e476009856ac8e3e9f9b48"); IDigest digest = new Sha256Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("1b8234e4a0c9f674fd6f29965bd03df4a8d30b17cf95b058ac46bc2fe9d8ec79a004a2e11165ae3131b9b9440abf9a6fded0d31af468aa56fee00158");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("73781a39ab0f3cdae0d8ea9649ecbe9b");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA256_AFTER_FIXED_32_BITS()
        {
            string name = "HMAC_SHA256_AFTER_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("ec8674a48a7baf28f865e63a3e8313fd55a09c8a46fb491916a871d1e65ab7f4"); IDigest digest = new Sha256Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("808772849ce4e97060618f8e510419a82d78a72ff265aa247335069fc73eca8df5276c850b5f052f0551da5319bb9e39318a820b167c6f999c67d4ae");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("9417ee14f9ebeb2e2c7bce18aa56a1a5");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA256_MIDDLE_FIXED_8_BITS()
        {
            string name = "HMAC_SHA256_MIDDLE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("6fd0f7b67db5b9ef0fd21d4408dae15af5524b00e8d583e9872760ebf6d53397"); IDigest digest = new Sha256Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("fc67e8cd41dcb339fe376892b3c196ad4d70573e031cebac67bb32a00a878d0064446a98fcce9ccaa6d8d388e3cbdfb8dcc6");
                byte[] DataAfterCtrData = Hex.Decode("e9798604020da472f161");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("b24833fe4a28f84fb4341bc42abc4ae6");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA256_MIDDLE_FIXED_16_BITS()
        {
            string name = "HMAC_SHA256_MIDDLE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("e4f6a0b7bc8941f115f9523a050f527687213a4236bb8047d9ec6671be35278c"); IDigest digest = new Sha256Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("883c38f759847b142a05ba28152a391b826468fda0a269d55248d1c3daf2e66fe91c20b85c57f6b5464903bc93500e5bee04");
                byte[] DataAfterCtrData = Hex.Decode("9c52c875593e59580155");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("c9f14ec1dbc676ac650ffcd143bf5c5c");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA256_MIDDLE_FIXED_24_BITS()
        {
            string name = "HMAC_SHA256_MIDDLE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("367fc005cb2565a92cf8b1cfdf4869ccad04c9fdfc8250d027d82a33cd0b36e0"); IDigest digest = new Sha256Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("f3a71b1465972703773ec0c92681bc27e626587fe683a07fed69c9bb0a1053afa1ec187cf26fa9dd8c690f415af98d442470");
                byte[] DataAfterCtrData = Hex.Decode("b9dc98f750c71d74e243");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("67301e0b417c5af335caee31b3e620c3");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA256_MIDDLE_FIXED_32_BITS()
        {
            string name = "HMAC_SHA256_MIDDLE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("60e118235b5fca0b15f8dbe6109b6a1a2f9d0d6f69cecfb5f65d4eb5a1c00a36"); IDigest digest = new Sha256Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("3c04bf77b146ef5842daafe19edb9530b7d19b3519aa5c7e797ca5cea0d82ddea484d87d735e3541cf0ba1505cf5c45d8067");
                byte[] DataAfterCtrData = Hex.Decode("9803f3f48ea0a23e2856");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("d296bb7b1707c9109d19abf026c141f8");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA384_BEFORE_FIXED_8_BITS()
        {
            string name = "HMAC_SHA384_BEFORE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("0be1999848a7a14a555649048fcadf2f644304d163190dc9b23a21b80e3c8c373515d6267d9c5cfd31b560ffd6a2cd5c"); IDigest digest = new Sha384Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("11340cfbdb40f20f84cac4b8455bdd76c730adcecd0484af9011bacd46e22ff2d87755dfb4d5ba7217c37cb83259bdbe0983cc716adc2e6c826ed53c");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("c2ea7454de25afb27065f4676a392385");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA384_BEFORE_FIXED_16_BITS()
        {
            string name = "HMAC_SHA384_BEFORE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("26ef897e4b617b597f766ec8d8ccf44c543e790a7d218f029dcb4a3695ae2caccce9d3e935f6741581f2f53e49cd46f8"); IDigest digest = new Sha384Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("bc2c728f9dc6db426dd4e85fdb493826a31fec0607644209f9bf2264b6401b5db3004c1a76aa08d93f08d3d9e2ba434b682e480004fb0d9271a8e8cd");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("a43d31f07f0ee484455ae11805803f60");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA384_BEFORE_FIXED_24_BITS()
        {
            string name = "HMAC_SHA384_BEFORE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("4fab4f1e3512b5f443ec31d2f6425d5f0fc13a5f82c83f72788a48a1bd499495ff18fb7acc0d4c1666c99db12e28f725"); IDigest digest = new Sha384Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("f0f010f99fbd8ec1bd0f23cd12bb41b2b8acb8713bb031f927e439f616e6ae27aed3f5582f8206893deea1204df125cedce35ce2b01b32bcefb388fd");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("c3c263b5aa6d0cfe5304a7c9d21a44ba");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA384_BEFORE_FIXED_32_BITS()
        {
            string name = "HMAC_SHA384_BEFORE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("216ed044769c4c3908188ece61601af8819c30f501d12995df608e06f5e0e607ab54f542ee2da41906dfdb4971f20f9d"); IDigest digest = new Sha384Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("638e9506a2c7be69ea346b84629a010c0e225b7548f508162c89f29c1ddbfd70472c2b58e7dc8aa6a5b06602f1c8ed4948cda79c62708218e26ac0e2");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("d4b144bb40c7cabed13963d7d4318e72");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA384_AFTER_FIXED_8_BITS()
        {
            string name = "HMAC_SHA384_AFTER_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("a63c1e7cb3b65787dcece40a6707a3d1211875dc2dfe3442c186bccc9268b1e746f308ae4340821b31249836c752cb6f"); IDigest digest = new Sha384Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("1b370439c68c164c8ee6aea1250babf3adb77f8704f262bdf77e481660213067ec81b8c0491e6df2b42dce7f86e29906dab8c022f2a6dac1c1de5757");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("e65f13d21fb0349e9646b1f0d23910c7");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA384_AFTER_FIXED_16_BITS()
        {
            string name = "HMAC_SHA384_AFTER_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("b405fe54dd52824cf0c298f941878bfe08baf6c77f544b2331dda0cc488fb60e89ad4689053d2f83fa87573b69a6ff54"); IDigest digest = new Sha384Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("23212d6e35fecb50feb7c96ab387afbe5604a9658447cf372b18e2de2d119ae4f92e71b81f894510ef9abe3ee3b98b64d96365ebada29a5102dc162b");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("06b556696ecc5269f56ecd3bb81220a4");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA384_AFTER_FIXED_24_BITS()
        {
            string name = "HMAC_SHA384_AFTER_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("41d9d61dbf3ce97a65efb73a871a63171160af827a4c29e0637ec07c3d04c32493fff643b86ebc91a73e197d787323cb"); IDigest digest = new Sha384Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("333f7e640f8a520601cbe5abfe0235031560501bb722918547dcd9313ca77edf207c088400389a2f91f69a5cb3598bc1aa1897eb2b8f8faba8d3781c");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("31121ceaa2246e44e924a1e74861684b");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA384_AFTER_FIXED_32_BITS()
        {
            string name = "HMAC_SHA384_AFTER_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("0afcbfc7257a9d2385a559dbe218f05bac917b6223ab50c7452eb37715e617f3878c463b15fb5b98e98c61182a5df745"); IDigest digest = new Sha384Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("bf9f949e4599a6aa5dfd415e38c155934b93bb5b784080ae234d8a6d731a46787ade4e828f123cf0af8dbb9e4169c0b114d834cdf574fbe913e90f85");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("8d6e5473338b67f17270a4f692abf964");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA384_MIDDLE_FIXED_8_BITS()
        {
            string name = "HMAC_SHA384_MIDDLE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("0f5541afd9cfa90bd50e1e85570f65a6df52bf095066cdcbd4e315771e9e0e79d10397f6e65404c504f0a32d22abd18b"); IDigest digest = new Sha384Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("f786505898ec51ad62cdd5a8f0f5704c0d3695e9d896df81b419b7c779aca7123857f4fc2080b838424639ad3fd0c0699247");
                byte[] DataAfterCtrData = Hex.Decode("071e59d0b5ece3908610");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("62bc4ed7ff05f418ad6ea3668e43d840");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA384_MIDDLE_FIXED_16_BITS()
        {
            string name = "HMAC_SHA384_MIDDLE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("2fdfe31fc474ee16d4720224cffa1d45213bbce5b7c3252415e40c57980cfe8d1c6f21fad1efb45c67e927f4d803ee3e"); IDigest digest = new Sha384Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("859b5182957ddd103f260881176bad643a44133904970a65624f089e67ecbc8d03d95813226105b9b2d8fdfd9dd3d32c62d2");
                byte[] DataAfterCtrData = Hex.Decode("e97ce65057ad64fe300a");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("9f5dae27f4045d41c117b166354e4b81");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA384_MIDDLE_FIXED_24_BITS()
        {
            string name = "HMAC_SHA384_MIDDLE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("dfbb581823c48942933ba98b8c375da2d8e3dddbea5008661b1796652da6c1f355e27a2bc5dd30e74780e6079e1682b4"); IDigest digest = new Sha384Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("ee7fea1606bee7c21f5ba847b5016826d1ab39c1962f6eaf3a454f0d101e58ea406d12f15ef67fc8b2b21653cfe92751f735");
                byte[] DataAfterCtrData = Hex.Decode("3faee91c54e2ae42fcf2");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("4053e986be8a84172f4b4c5c687e603b");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA384_MIDDLE_FIXED_32_BITS()
        {
            string name = "HMAC_SHA384_MIDDLE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("dabfd087e001767172bfc631a0d243494adbf243112a4525e24a1ce279854a4635621b17334360d3818ed4feeb28d2fd"); IDigest digest = new Sha384Digest();
                IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("8e65bda5193e65bc834c39061e0b5adfc11d6617737b8d8840f344d218af772192ef2d45527cde0dfb17aac540449c93bd91");
                byte[] DataAfterCtrData = Hex.Decode("c6bf28ad1b04d8e5ad93");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("87f063a791e28781073c4091ad80ef46");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA512_BEFORE_FIXED_8_BITS()
        {
            string name = "HMAC_SHA512_BEFORE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("6ea2c385bb3e7bbafc2225cee1d3ee103ce300c1fdf033d0c1e99c57e6a596e037020838e857c0434040b58a5ca5410be672b888ef9955bdd54eb6a67416ff6a"); IDigest digest = new Sha512Digest(); IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("be119901ed8679b243508b97663f35da322774d7d2012d6557da6657c1176a115ebc73b0f1bfa1dba6b8c3b124f0a47cff2998b230c955b0ea809784");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("e0755fa6f116ef7a8e8361f47fd57511");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA512_BEFORE_FIXED_16_BITS()
        {
            string name = "HMAC_SHA512_BEFORE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("bb0c55c7201ceb2e1369a6c49e2cdc1ae5e4cd1d64638105072c3a9172b2fa6a127c4d6d55132585fb2644b5ae3cf9d347875e0d0bf80945eaabef3b4319605e"); IDigest digest = new Sha512Digest(); IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("89bf925033f00635c100e2c88a98ad9f08cd6a002b934617d4ebfffc0fe9bca1d19bd942da3704da127c7493cc62c67f507c415e4cb67d7d0be70005");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("05efd62522beb9bfff6492ecd24501a7");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA512_BEFORE_FIXED_24_BITS()
        {
            string name = "HMAC_SHA512_BEFORE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("d10933b0683f6787c33eccea1c311b8444270504fb3980bfd56443ba4068722184c31541d9174f71068b7789440bc34cec456e115067f9c65a5f2883c6868204"); IDigest digest = new Sha512Digest(); IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("dcb2ea8d715821d6393bd49a3e35f69a6c2519edb614f80fbc3f7ae1d65ff4a04c499e75d08819a09092ddaadba510e03cb2ac898804590dbd61fb7e");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("876d73040d03d569e2fcae33b241d98e");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA512_BEFORE_FIXED_32_BITS()
        {
            string name = "HMAC_SHA512_BEFORE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("dd5dbd45593ee2ac139748e7645b450f223d2ff297b73fd71cbcebe71d41653c950b88500de5322d99ef18dfdd30428294c4b3094f4c954334e593bd982ec614"); IDigest digest = new Sha512Digest(); IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("b50b0c963c6b3034b8cf19cd3f5c4ebe4f4985af0c03e575db62e6fdf1ecfe4f28b95d7ce16df85843246e1557ce95bb26cc9a21974bbd2eb69e8355");
                KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("e5993bf9bd2aa1c45746042e12598155");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA512_AFTER_FIXED_8_BITS()
        {
            string name = "HMAC_SHA512_AFTER_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("ab052ef2e9137415060435b9a73a67623e07f3467981fe8093c440973658851028c86e44a1fd9100b413792f14e257683aa74b83ecd96d24c862c2263a496cfb"); IDigest digest = new Sha512Digest(); IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("668831e2701803581eb9083a0928cc00d83a3c19ca4df061d155a880a66ba24857ad6f4bd7a67382215b5b9d81b37737d74f7a5ef78486aeea2f9ac1");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("6ec2b089107021463bae15f8f5c771ab");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA512_AFTER_FIXED_16_BITS()
        {
            string name = "HMAC_SHA512_AFTER_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("8c38d9f55e75b83b92ca7cda2df3e384a47445620aaa5b74ec74399a2ad5d3ba2b65970916e49bd0b01ec03563c3652962a3438a1c06bfbf6c6bd7586b41841a"); IDigest digest = new Sha512Digest(); IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("45668072071d4f12af25cb2140a7e2f09ef62942bceb5ba9b87c57e233b3656a572ae38a1466566a8be649c79f479c255cb8d3821c02c75cb5171884");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("06332aacfe5942eaa931902d83f692ad");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA512_AFTER_FIXED_24_BITS()
        {
            string name = "HMAC_SHA512_AFTER_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("63bd6f4163b34ece4477605db93e6eb7f4a8c0707471b081d8bdfce44e5823b62d346fa60a3d338c675eba7e5c0920f50197872af24a124d3bb20c45d30dbd99"); IDigest digest = new Sha512Digest(); IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("699bc682c47f969db1d62ffd906711d34ebdb9fccd597e6f5ecc7d7258b8574947307cafa369ece5a4da3cc6d1fcc669f51db24a10112cc5cd9070dc");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("6cedc5f5cf879f9f758f0de04f2ce145");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA512_AFTER_FIXED_32_BITS()
        {
            string name = "HMAC_SHA512_AFTER_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("e482268362f80ca7f777b4202d03234a5f0ed59b578a6b8792ff54d900af6940beacc7d3fb801661f64392e5658d4f82e3b5d63b190a44c032b6a8ac51a2acc2"); IDigest digest = new Sha512Digest(); IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] fixedInputData = Hex.Decode("9ce99ad9a90f45785e749a66df7489c4200904141391274dfb24a5e4ea8cafc87f920b33fcbac0d93fc59d4bf558b7f2a9e1435cb454a4f180300e17");
                KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("cc99953cc0d7b0da795293675442528d");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA512_MIDDLE_FIXED_8_BITS()
        {
            string name = "HMAC_SHA512_MIDDLE_FIXED_8_BITS ";
            {
                int r = 8;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("7b7ed39b91cdbc0c0b3cfed4830a1c5b47971c80054d3c82b75a98e98ac06adf86307afdeb15a7d83d896cc8dc0c0f8d7eb450ba31f4c12ec6fb131778cc2dc0"); IDigest digest = new Sha512Digest(); IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("e4e853508f5b07a1c8e7033d0d683affdac3b7cd5931c53933b49bd30ec149300735cfc34a307dcb609a26c9378e8f75bc5f");
                byte[] DataAfterCtrData = Hex.Decode("689823dbc6bf6d3c097b");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("d0ad633ce6ad0d4ed5ab9247177de926");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA512_MIDDLE_FIXED_16_BITS()
        {
            string name = "HMAC_SHA512_MIDDLE_FIXED_16_BITS ";
            {
                int r = 16;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("3ee8a94d1a45078967a76f1094923fb0f67691bf54159d100a0c2c9dc12cac84c394a9a1efb05df78e0f03342b9129b2bf06d1e4f6bd25965fcdf2ecc74f4a2c"); IDigest digest = new Sha512Digest(); IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("5527ea9f8ffa12569dc4c1e95a92b213072b50db9dae2a53d8a0d63640749057f3c936377400d69387df468e1a54cf19530c");
                byte[] DataAfterCtrData = Hex.Decode("e72f4c2b03d7ed637ad5");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("e3090abfc11f8b709207105d4ed46505");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA512_MIDDLE_FIXED_24_BITS()
        {
            string name = "HMAC_SHA512_MIDDLE_FIXED_24_BITS ";
            {
                int r = 24;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode("5572ceb20ce4cb93b4a3781e55846f4d012fe5598924beb134a17dedf2b59da3bc997d5a105b423cf49849c33bbcef564a993c8a648b4d8fb567f4c08030f9b9"); IDigest digest = new Sha512Digest(); IMac prf = new HMac(digest); KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData = Hex.Decode("bca2eda0ac96d53e7f94f41ef880cd2dcfccd2bd0c116a87c7e6485fe7535469da538c92f6d6c8443f480d10ebfca36e441d");
                byte[] DataAfterCtrData = Hex.Decode("4072f6e842886be123d3");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("abc01ab53b61ce1cebf3038b42a4a854");

                compareKO(name, koGenerated, koVectors);
            }
        }

        [Test]
        public void TestHMAC_SHA512_MIDDLE_FIXED_32_BITS()
        {
            string name = "HMAC_SHA512_MIDDLE_FIXED_32_BITS ";
            {
                int r = 32;
                //int count = 0;
                int l = 128;
                byte[] ki = Hex.Decode(
                    "4cfbc55d3a2334c71787ea1c4b9426106b1ba327a909d54fc9b3113f4b74617fec68858a05ea9943fffb0623af633f2a16ae87afa37e3f304da41f7b83e4cb91");
                IDigest digest = new Sha512Digest();
                IMac prf = new HMac(digest);
                KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                byte[] DataBeforeCtrData =
                    Hex.Decode(
                        "2d6b4804ed912a9bf3005db33c221c6793ff33ffc90bf559811d63fdd0d06f8f36da610f2d555ea37bf3f1220a8e8a8a8629");
                byte[] DataAfterCtrData = Hex.Decode("adbd9e4688b45575d385");
                KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                gen.Init(param);
                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = Hex.Decode("5260b2e61f6ad15e775a793c699c5583");

                compareKO(name, koGenerated, koVectors);
            }
        }

        private static void compareKO(
            string name, byte[] calculatedOKM, byte[] testOKM)
        {
            if (!Arrays.AreEqual(calculatedOKM, testOKM))
            {
                throw new TestFailedException(new SimpleTestResult(
                    false, name + " failed"));
            }
        }

        public override string Name
        {
            get { return "KdfCounterTest"; }
        }


        public override void PerformTest()
        {
            TestCMAC_AES128_BEFORE_FIXED_8_BITS();
            TestCMAC_AES128_BEFORE_FIXED_16_BITS();
            TestCMAC_AES128_BEFORE_FIXED_24_BITS();
            TestCMAC_AES128_BEFORE_FIXED_32_BITS();
            TestCMAC_AES128_AFTER_FIXED_8_BITS();
            TestCMAC_AES128_AFTER_FIXED_16_BITS();
            TestCMAC_AES128_AFTER_FIXED_24_BITS();
            TestCMAC_AES128_AFTER_FIXED_32_BITS();
            TestCMAC_AES128_MIDDLE_FIXED_8_BITS();
            TestCMAC_AES128_MIDDLE_FIXED_16_BITS();
            TestCMAC_AES128_MIDDLE_FIXED_24_BITS();
            TestCMAC_AES128_MIDDLE_FIXED_32_BITS();
            TestCMAC_AES192_BEFORE_FIXED_8_BITS();
            TestCMAC_AES192_BEFORE_FIXED_16_BITS();
            TestCMAC_AES192_BEFORE_FIXED_24_BITS();
            TestCMAC_AES192_BEFORE_FIXED_32_BITS();
            TestCMAC_AES192_AFTER_FIXED_8_BITS();
            TestCMAC_AES192_AFTER_FIXED_16_BITS();
            TestCMAC_AES192_AFTER_FIXED_24_BITS();
            TestCMAC_AES192_AFTER_FIXED_32_BITS();
            TestCMAC_AES192_MIDDLE_FIXED_8_BITS();
            TestCMAC_AES192_MIDDLE_FIXED_16_BITS();
            TestCMAC_AES192_MIDDLE_FIXED_24_BITS();
            TestCMAC_AES192_MIDDLE_FIXED_32_BITS();
            TestCMAC_AES256_BEFORE_FIXED_8_BITS();
            TestCMAC_AES256_BEFORE_FIXED_16_BITS();
            TestCMAC_AES256_BEFORE_FIXED_24_BITS();
            TestCMAC_AES256_BEFORE_FIXED_32_BITS();
            TestCMAC_AES256_AFTER_FIXED_8_BITS();
            TestCMAC_AES256_AFTER_FIXED_16_BITS();
            TestCMAC_AES256_AFTER_FIXED_24_BITS();
            TestCMAC_AES256_AFTER_FIXED_32_BITS();
            TestCMAC_AES256_MIDDLE_FIXED_8_BITS();
            TestCMAC_AES256_MIDDLE_FIXED_16_BITS();
            TestCMAC_AES256_MIDDLE_FIXED_24_BITS();
            TestCMAC_AES256_MIDDLE_FIXED_32_BITS();
            TestCMAC_TDES2_BEFORE_FIXED_8_BITS();
            TestCMAC_TDES2_BEFORE_FIXED_16_BITS();
            TestCMAC_TDES2_BEFORE_FIXED_24_BITS();
            TestCMAC_TDES2_BEFORE_FIXED_32_BITS();
            TestCMAC_TDES2_AFTER_FIXED_8_BITS();
            TestCMAC_TDES2_AFTER_FIXED_16_BITS();
            TestCMAC_TDES2_AFTER_FIXED_24_BITS();
            TestCMAC_TDES2_AFTER_FIXED_32_BITS();
            TestCMAC_TDES2_MIDDLE_FIXED_8_BITS();
            TestCMAC_TDES2_MIDDLE_FIXED_16_BITS();
            TestCMAC_TDES2_MIDDLE_FIXED_24_BITS();
            TestCMAC_TDES2_MIDDLE_FIXED_32_BITS();
            TestCMAC_TDES3_BEFORE_FIXED_8_BITS();
            TestCMAC_TDES3_BEFORE_FIXED_16_BITS();
            TestCMAC_TDES3_BEFORE_FIXED_24_BITS();
            TestCMAC_TDES3_BEFORE_FIXED_32_BITS();
            TestCMAC_TDES3_AFTER_FIXED_8_BITS();
            TestCMAC_TDES3_AFTER_FIXED_16_BITS();
            TestCMAC_TDES3_AFTER_FIXED_24_BITS();
            TestCMAC_TDES3_AFTER_FIXED_32_BITS();
            TestCMAC_TDES3_MIDDLE_FIXED_8_BITS();
            TestCMAC_TDES3_MIDDLE_FIXED_16_BITS();
            TestCMAC_TDES3_MIDDLE_FIXED_24_BITS();
            TestCMAC_TDES3_MIDDLE_FIXED_32_BITS();
            TestHMAC_SHA1_BEFORE_FIXED_8_BITS();
            TestHMAC_SHA1_BEFORE_FIXED_16_BITS();
            TestHMAC_SHA1_BEFORE_FIXED_24_BITS();
            TestHMAC_SHA1_BEFORE_FIXED_32_BITS();
            TestHMAC_SHA1_AFTER_FIXED_8_BITS();
            TestHMAC_SHA1_AFTER_FIXED_16_BITS();
            TestHMAC_SHA1_AFTER_FIXED_24_BITS();
            TestHMAC_SHA1_AFTER_FIXED_32_BITS();
            TestHMAC_SHA1_MIDDLE_FIXED_8_BITS();
            TestHMAC_SHA1_MIDDLE_FIXED_16_BITS();
            TestHMAC_SHA1_MIDDLE_FIXED_24_BITS();
            TestHMAC_SHA1_MIDDLE_FIXED_32_BITS();
            TestHMAC_SHA224_BEFORE_FIXED_8_BITS();
            TestHMAC_SHA224_BEFORE_FIXED_16_BITS();
            TestHMAC_SHA224_BEFORE_FIXED_24_BITS();
            TestHMAC_SHA224_BEFORE_FIXED_32_BITS();
            TestHMAC_SHA224_AFTER_FIXED_8_BITS();
            TestHMAC_SHA224_AFTER_FIXED_16_BITS();
            TestHMAC_SHA224_AFTER_FIXED_24_BITS();
            TestHMAC_SHA224_AFTER_FIXED_32_BITS();
            TestHMAC_SHA224_MIDDLE_FIXED_8_BITS();
            TestHMAC_SHA224_MIDDLE_FIXED_16_BITS();
            TestHMAC_SHA224_MIDDLE_FIXED_24_BITS();
            TestHMAC_SHA224_MIDDLE_FIXED_32_BITS();
            TestHMAC_SHA256_BEFORE_FIXED_8_BITS();
            TestHMAC_SHA256_BEFORE_FIXED_16_BITS();
            TestHMAC_SHA256_BEFORE_FIXED_24_BITS();
            TestHMAC_SHA256_BEFORE_FIXED_32_BITS();
            TestHMAC_SHA256_AFTER_FIXED_8_BITS();
            TestHMAC_SHA256_AFTER_FIXED_16_BITS();
            TestHMAC_SHA256_AFTER_FIXED_24_BITS();
            TestHMAC_SHA256_AFTER_FIXED_32_BITS();
            TestHMAC_SHA256_MIDDLE_FIXED_8_BITS();
            TestHMAC_SHA256_MIDDLE_FIXED_16_BITS();
            TestHMAC_SHA256_MIDDLE_FIXED_24_BITS();
            TestHMAC_SHA256_MIDDLE_FIXED_32_BITS();
            TestHMAC_SHA384_BEFORE_FIXED_8_BITS();
            TestHMAC_SHA384_BEFORE_FIXED_16_BITS();
            TestHMAC_SHA384_BEFORE_FIXED_24_BITS();
            TestHMAC_SHA384_BEFORE_FIXED_32_BITS();
            TestHMAC_SHA384_AFTER_FIXED_8_BITS();
            TestHMAC_SHA384_AFTER_FIXED_16_BITS();
            TestHMAC_SHA384_AFTER_FIXED_24_BITS();
            TestHMAC_SHA384_AFTER_FIXED_32_BITS();
            TestHMAC_SHA384_MIDDLE_FIXED_8_BITS();
            TestHMAC_SHA384_MIDDLE_FIXED_16_BITS();
            TestHMAC_SHA384_MIDDLE_FIXED_24_BITS();
            TestHMAC_SHA384_MIDDLE_FIXED_32_BITS();
            TestHMAC_SHA512_BEFORE_FIXED_8_BITS();
            TestHMAC_SHA512_BEFORE_FIXED_16_BITS();
            TestHMAC_SHA512_BEFORE_FIXED_24_BITS();
            TestHMAC_SHA512_BEFORE_FIXED_32_BITS();
            TestHMAC_SHA512_AFTER_FIXED_8_BITS();
            TestHMAC_SHA512_AFTER_FIXED_16_BITS();
            TestHMAC_SHA512_AFTER_FIXED_24_BITS();
            TestHMAC_SHA512_AFTER_FIXED_32_BITS();
            TestHMAC_SHA512_MIDDLE_FIXED_8_BITS();
            TestHMAC_SHA512_MIDDLE_FIXED_16_BITS();
            TestHMAC_SHA512_MIDDLE_FIXED_24_BITS();
            TestHMAC_SHA512_MIDDLE_FIXED_32_BITS();

        }
    }
}