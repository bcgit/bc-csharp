using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class CrystalsDilithiumTest
    {
        private static readonly Dictionary<string, DilithiumParameters> Parameters = new Dictionary<string, DilithiumParameters>()
        {
            { "PQCsignKAT_Dilithium2.rsp", DilithiumParameters.Dilithium2 },
            { "PQCsignKAT_Dilithium3.rsp", DilithiumParameters.Dilithium3 },
            { "PQCsignKAT_Dilithium5.rsp", DilithiumParameters.Dilithium5 },
            { "PQCsignKAT_Dilithium2-AES.rsp", DilithiumParameters.Dilithium2Aes },
            { "PQCsignKAT_Dilithium3-AES.rsp", DilithiumParameters.Dilithium3Aes },
            { "PQCsignKAT_Dilithium5-AES.rsp", DilithiumParameters.Dilithium5Aes },
        };

        private static readonly string[] TestVectorFiles =
        {
            "PQCsignKAT_Dilithium2.rsp",
            "PQCsignKAT_Dilithium3.rsp",
            "PQCsignKAT_Dilithium5.rsp",
        };

        private static readonly string[] TestVectorFilesAes =
        {
            "PQCsignKAT_Dilithium2-AES.rsp",
            "PQCsignKAT_Dilithium3-AES.rsp",
            "PQCsignKAT_Dilithium5-AES.rsp",
        };

        [TestCaseSource(nameof(TestVectorFiles))]
        [Parallelizable(ParallelScope.All)]
        public void TV(string testVectorFile)
        {
            RunTestVectorFile(testVectorFile);
        }

        [TestCaseSource(nameof(TestVectorFilesAes))]
        [Parallelizable(ParallelScope.All)]
        public void TVAes(string testVectorFile)
        {
            RunTestVectorFile(testVectorFile);
        }

        [Test]
        public void TestKeyEncodingDilithium2()
        {
            byte[] altEncKey = Base64.Decode("oED4ZvqhK4kChPclP5VhOPvvnwof3QeTFq/zR5UtSr6SYicBkpe1TkafnSk5whDHgEp8imVwfeP2LbSopHb5KQuUFstGqsdII9o8Zf+50yempJ1+C5G64KfQlqkI8/Y6cShWWNgeWm/5OGyxhF0hYVGIwaTTs6AN3QaPjSutLPNdZ82Vd4BSNB5dzZMaoYV619rNO7HGlfwrWkyCoDVQftpgw4NjiAnJ0BPcDJTzPVD3cq3Dw5f14AwNsUijLZ4CuRzzCBBx0B+SbIruEnGbDNhfzp3FdDg2sy/hRqD6/0gzOBExzLT8ofBE6D9VcmiPT+KgLbiObhZt+mjzGGE3wnXgmklX5Qr/d7kyamm4tq3xiKm58/VdkB3ASt+ULo1jXQtuoXVkn7vfT/1LAVbJ6QIqvxcQknDj2j2oUSWYLz48qfgNWtbM/EOZ8WBaV9UxO7Sd5wF+/wiVUxrMC+3BdrJnWSP00s7AJBH4NdQfU7E6uK1BhJEDLZaiRshi1lnu7PfKLdKSIyRL73VsmjQhONXtyBy1gG876DSa846d3ppx+kd2FxR5QRtUT5Y3E1lgxYlyInjmRzFoEc6TXyhYFYptvyFKV7FUxClYCLYbE4YPBnbJ3WyaqtmJNCueMlNYGSYR/7yLOjdj8O2j21q+fVI1z9cxOx4A2xHMNiX+mvVaQQLOIQbsbCeKkR6HhnAgblU8ge7n6EFN6hN+24R7FCaCKCQy3HTngw+FBJJYMlcAIvno3KQj25g8nR9uQQ57DNla2yLgGC02cG0ECemIP3nroqohcENydsuaKkzVtDenGakcpERACf4RXqbcvwuSEEH1IU5SjUGTEJgd8/BI/Mgicc5DEyZM18ONrhSpH8oTVuxJ7DAm1MQtmqkHEB71UWAEfPrmcJXz/p+ih5q4nl8k6X/48Du2SEC6YeMMrXUR8JzP3kEVULLaBxXJMtIumnsecAndoxAGdhxY+rJCPPSimc+navloDZ3xO9+nqimeOuvnKAZGxr7aiWt+h4xL+H1ZkO/NlMdWhbIeyohJhtZ2pav8XDZLAbJmNNGJH8/4RjG3TsA5rEoqiulnTgtWNj7POiITmPrHoG+d88AB5JalRZm1Mm6nSdKH96U2dN0rZWgP+qc6xl8/Rn6jMnOY9dPTpVq9IrTAiqeBIj5vpAn0Y4oXuCEn3hjFeDxvcSqbAFAE8Tf+GABHQRVBapw0tL3JW4GKT92BlKmDzqVu7XQIuTJ4wPu1WQ95DbGzIGrh45x0UbU1h9S1xWcJLCy1RnoImocvvI3T0JpChuZvSmThNauV3dhoOojh522X38uxuXfgl7ziQmUIPR/YI9CUIm7mKB9el8HlgSa35HZaWWRGuik6ceEN9s0ZkWNOlREth+FDD7JoKiZh8ehgfK/1sQM/2c/8fsyysGeFrmSAkp9jwGKIvd+feJneoUgxZg2mzMmVjZM4J6vjseOUypzKeb1zRzNCw6UAF6LJNDcBzmlYk0gjMibofI/UaWaPEnXyiaFEFfWlYPFvDcd/ehPm7ft9tpLYnbx6ETW8FMHvnbrXTdNeZlU9UWO5NpSW+WbGTKcbU8ZJBECN49HYBiv0OBHWjGYj8hb/1ig05m4/uyr6zOG8So87CDR8FfZMk+3YOf2hmb5LzdRskcMABDOdNeKz8Bnc0uIuc8MqtGWtGgPiDpnj8R123MO30BpYugpQhLZm5wjX+i4ZMkj2DrBY1TAlo1JSR0LTnspR4IA4eQ==");
            byte[] altSubPubEnc = Base64.Decode("MIIFODANBgsrBgEEAQKCCwcEBAOCBSUABIIFIKBA+Gb6oSuJAoT3JT+VYTj7758KH90Hkxav80eVLUq+kmInAZKXtU5Gn50pOcIQx4BKfIplcH3j9i20qKR2+SkLlBbLRqrHSCPaPGX/udMnpqSdfguRuuCn0JapCPP2OnEoVljYHlpv+ThssYRdIWFRiMGk07OgDd0Gj40rrSzzXWfNlXeAUjQeXc2TGqGFetfazTuxxpX8K1pMgqA1UH7aYMODY4gJydAT3AyU8z1Q93Ktw8OX9eAMDbFIoy2eArkc8wgQcdAfkmyK7hJxmwzYX86dxXQ4NrMv4Uag+v9IMzgRMcy0/KHwROg/VXJoj0/ioC24jm4Wbfpo8xhhN8J14JpJV+UK/3e5MmppuLat8YipufP1XZAdwErflC6NY10LbqF1ZJ+730/9SwFWyekCKr8XEJJw49o9qFElmC8+PKn4DVrWzPxDmfFgWlfVMTu0necBfv8IlVMazAvtwXayZ1kj9NLOwCQR+DXUH1OxOritQYSRAy2WokbIYtZZ7uz3yi3SkiMkS+91bJo0ITjV7cgctYBvO+g0mvOOnd6acfpHdhcUeUEbVE+WNxNZYMWJciJ45kcxaBHOk18oWBWKbb8hSlexVMQpWAi2GxOGDwZ2yd1smqrZiTQrnjJTWBkmEf+8izo3Y/Dto9tavn1SNc/XMTseANsRzDYl/pr1WkECziEG7GwnipEeh4ZwIG5VPIHu5+hBTeoTftuEexQmgigkMtx054MPhQSSWDJXACL56NykI9uYPJ0fbkEOewzZWtsi4BgtNnBtBAnpiD9566KqIXBDcnbLmipM1bQ3pxmpHKREQAn+EV6m3L8LkhBB9SFOUo1BkxCYHfPwSPzIInHOQxMmTNfDja4UqR/KE1bsSewwJtTELZqpBxAe9VFgBHz65nCV8/6fooeauJ5fJOl/+PA7tkhAumHjDK11EfCcz95BFVCy2gcVyTLSLpp7HnAJ3aMQBnYcWPqyQjz0opnPp2r5aA2d8Tvfp6opnjrr5ygGRsa+2olrfoeMS/h9WZDvzZTHVoWyHsqISYbWdqWr/Fw2SwGyZjTRiR/P+EYxt07AOaxKKorpZ04LVjY+zzoiE5j6x6BvnfPAAeSWpUWZtTJup0nSh/elNnTdK2VoD/qnOsZfP0Z+ozJzmPXT06VavSK0wIqngSI+b6QJ9GOKF7ghJ94YxXg8b3EqmwBQBPE3/hgAR0EVQWqcNLS9yVuBik/dgZSpg86lbu10CLkyeMD7tVkPeQ2xsyBq4eOcdFG1NYfUtcVnCSwstUZ6CJqHL7yN09CaQobmb0pk4TWrld3YaDqI4edtl9/Lsbl34Je84kJlCD0f2CPQlCJu5igfXpfB5YEmt+R2WllkRropOnHhDfbNGZFjTpURLYfhQw+yaComYfHoYHyv9bEDP9nP/H7MsrBnha5kgJKfY8BiiL3fn3iZ3qFIMWYNpszJlY2TOCer47HjlMqcynm9c0czQsOlABeiyTQ3Ac5pWJNIIzIm6HyP1GlmjxJ18omhRBX1pWDxbw3Hf3oT5u37fbaS2J28ehE1vBTB7526103TXmZVPVFjuTaUlvlmxkynG1PGSQRAjePR2AYr9DgR1oxmI/IW/9YoNOZuP7sq+szhvEqPOwg0fBX2TJPt2Dn9oZm+S83UbJHDAAQznTXis/AZ3NLiLnPDKrRlrRoD4g6Z4/EddtzDt9AaWLoKUIS2ZucI1/ouGTJI9g6wWNUwJaNSUkdC057KUeCAOHk=");

            AsymmetricKeyParameter altPubDec = PqcPublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(altSubPubEnc));
            Assert.AreEqual(altEncKey, ((DilithiumPublicKeyParameters)altPubDec).GetEncoded());
    
            Security.SecureRandom random = new Security.SecureRandom();
            DilithiumKeyGenerationParameters kparam = new DilithiumKeyGenerationParameters(random, DilithiumParameters.Dilithium2);
            DilithiumKeyPairGenerator kpg = new DilithiumKeyPairGenerator();
            kpg.Init(kparam);
            AsymmetricCipherKeyPair ackp = kpg.GenerateKeyPair();

            AsymmetricKeyParameter pub = ackp.Public;
            AsymmetricKeyParameter priv = ackp.Private;

            AsymmetricKeyParameter pubDec = PqcPublicKeyFactory.CreateKey(PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub));
            AsymmetricKeyParameter privDec = PqcPrivateKeyFactory.CreateKey(PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(priv));

            Assert.AreEqual(((DilithiumPublicKeyParameters)pub).GetEncoded(), ((DilithiumPublicKeyParameters)pubDec).GetEncoded());
            Assert.AreEqual(((DilithiumPrivateKeyParameters)priv).GetEncoded(), ((DilithiumPrivateKeyParameters)privDec).GetEncoded());
        }

        [Test]
        public void TestKeyEncodingDilithium2Aes()
        {
            byte[] altEncKey = Base64.Decode("CKJBWPvTOpeLU/2y0fhlWLc9HKYgH2pAARm2IzwF927Nnnugbw4T7cmjtSfbD/e4CamjVdehDBPqYBWfbZumLD+EuPQUqWaCYDS9JcezFmFXACFHRQPwWDqwqvfuy7zeN4HVb/ygiNJI/mWNoqRn3Ffz59J2iPLr9xe8TUNgQ6VK3tVwIqkxAXv1GVX5MCJI0U2v7d00RnfEDnYL2AVZjSGe0fboKN74OrMTLlx2qN9a8uw21mcgvULBIItsppN7w+gSjOnqSg22wA2RojBNZRuQm4AVeZR6mPw0cYVSyBD3DSjPCWhwseJOACfxdaKgPUQOYlYvQLTTQ1O8fYsrmdF/8aisZ9oo7HVz5xC46AEIL2mp5eVGZJxFpvYyUet0JMFmDgv1PUtoja/EfORNM2T1+pHkv6InfyIDXS3+SMuH0S4qUCmhNtKV47L5uVUl0dfgzDdvsooEZ8iCT1z3nAWiaDNKbMEdYvY7/Qm2HtJIMzLyyXfD9kkwAGr/rzU4IyqK0cS97cVeeT86Zt0e4OtLXJnjhNpD4v+qukjnRVeov/tGzDUtohcAghTTArx3/E3ZEOrDzgagyHKu/3IefhVqndYMle8+NuYIjbN0J/CFOgIpL81ZgVgdCDrj0MWGhPwlUeQcDRnMqxrEtCeXO+X7v2A2USd7Nss0aQOdfN1VzBNV18IWQEeD37pQPyEsyWkLYr6WNyIEZ7gqOpHc4eyWCccI6n3f0Q2kN7YqcX3Gxgbxa8i9P81HxFHfEwabcsXZXmCUowqfGVfx+np2wyYP0uOQrER29vq99RyV1NgXkjtKW1scaVWUFHsaT4nluJjHQ46V77R7HvNZUcvLmKtqtqGAJoe74Aiy5Ft2PnNBNSFs9XQOpuNnZsoTLm29ZGI5FnXf59U7Qm4j9gYB1ra2KzWkzcbjyaPk2aPCPTZHcsp8cyp5V6n9jux5PoW1iJmxo40Rso3fS04bhgZxRbQzcEIPG2iwdpa5qiFD17AC8o6LSWjhxoNgRwHqC7vCdWJyLsCdvN6kkKjdG0DFJpylr/fiBgBj8pm/XdTSboIdrcKvmITcRHXlC02XzdzIehFGeDrDDn0/mCzMHqGnYIhbY1wMywP8BMzesv/igbTEhk/tKVa3//CaVCESO0Ma4HVVSxuuNvlgGSf7Af0n5fcqA/zSJe9iKEj0PPEr1VMbatzbTqBH7jQqQEgOEsG/E2vCtOJU343f1pPntdWwnj6k05s+IroRReGM9ZEDCw+r/QMGOQEbMljirwtM/2wkA/yzZcp1UqzLTQnY38jcJWpD+z0ld9wPFRf0EzJF6HE5ShljNS76qBvlcIJdem8mIO4wtDBY6cNMRc4TFcETz4qC0ws7bzXN47z7Cq6VtutOph+R0deGMvS1T6Ryn7MzmMefduDHvsUWPiBeD4siCPqxgy5Q2Bw5lxlAS7JQ8tuxkSISRs6wJCv8morF4CM2Z4IpQ6VWnFm4d+PyYIxPmHZ9d4HIOPUh7mzMJ2OG6ouOdK9a7W5cBCt23KMJMyiU1YqEGxRr4vyzlqCHfuqGTtke7kHUivMMtTHJnz1pd1r7pGn8AL8XcQNkoSt6u4GrNXMiA4Sj3ZFvIZeO7YjZ6RKv8CpRPYkE7qt0To5ZK3+Jt1cVGRG/9/tcBLCrBWwWQGCc0GaKhktI50hjDXZly+i2UW00p+LYEx7qWPZljYOoD+ued6Rog+HZ0Eit6/NZCAtK2quf/aDn0XaxoEfpuA==");
            byte[] altSubPubEnc = Base64.Decode("MIIFODANBgsrBgEEAQKCCwsEBAOCBSUABIIFIAiiQVj70zqXi1P9stH4ZVi3PRymIB9qQAEZtiM8BfduzZ57oG8OE+3Jo7Un2w/3uAmpo1XXoQwT6mAVn22bpiw/hLj0FKlmgmA0vSXHsxZhVwAhR0UD8Fg6sKr37su83jeB1W/8oIjSSP5ljaKkZ9xX8+fSdojy6/cXvE1DYEOlSt7VcCKpMQF79RlV+TAiSNFNr+3dNEZ3xA52C9gFWY0hntH26Cje+DqzEy5cdqjfWvLsNtZnIL1CwSCLbKaTe8PoEozp6koNtsANkaIwTWUbkJuAFXmUepj8NHGFUsgQ9w0ozwlocLHiTgAn8XWioD1EDmJWL0C000NTvH2LK5nRf/GorGfaKOx1c+cQuOgBCC9pqeXlRmScRab2MlHrdCTBZg4L9T1LaI2vxHzkTTNk9fqR5L+iJ38iA10t/kjLh9EuKlApoTbSleOy+blVJdHX4Mw3b7KKBGfIgk9c95wFomgzSmzBHWL2O/0Jth7SSDMy8sl3w/ZJMABq/681OCMqitHEve3FXnk/OmbdHuDrS1yZ44TaQ+L/qrpI50VXqL/7Rsw1LaIXAIIU0wK8d/xN2RDqw84GoMhyrv9yHn4Vap3WDJXvPjbmCI2zdCfwhToCKS/NWYFYHQg649DFhoT8JVHkHA0ZzKsaxLQnlzvl+79gNlEnezbLNGkDnXzdVcwTVdfCFkBHg9+6UD8hLMlpC2K+ljciBGe4KjqR3OHslgnHCOp939ENpDe2KnF9xsYG8WvIvT/NR8RR3xMGm3LF2V5glKMKnxlX8fp6dsMmD9LjkKxEdvb6vfUcldTYF5I7SltbHGlVlBR7Gk+J5biYx0OOle+0ex7zWVHLy5irarahgCaHu+AIsuRbdj5zQTUhbPV0DqbjZ2bKEy5tvWRiORZ13+fVO0JuI/YGAda2tis1pM3G48mj5Nmjwj02R3LKfHMqeVep/Y7seT6FtYiZsaONEbKN30tOG4YGcUW0M3BCDxtosHaWuaohQ9ewAvKOi0lo4caDYEcB6gu7wnVici7AnbzepJCo3RtAxSacpa/34gYAY/KZv13U0m6CHa3Cr5iE3ER15QtNl83cyHoRRng6ww59P5gszB6hp2CIW2NcDMsD/ATM3rL/4oG0xIZP7SlWt//wmlQhEjtDGuB1VUsbrjb5YBkn+wH9J+X3KgP80iXvYihI9DzxK9VTG2rc206gR+40KkBIDhLBvxNrwrTiVN+N39aT57XVsJ4+pNObPiK6EUXhjPWRAwsPq/0DBjkBGzJY4q8LTP9sJAP8s2XKdVKsy00J2N/I3CVqQ/s9JXfcDxUX9BMyRehxOUoZYzUu+qgb5XCCXXpvJiDuMLQwWOnDTEXOExXBE8+KgtMLO281zeO8+wqulbbrTqYfkdHXhjL0tU+kcp+zM5jHn3bgx77FFj4gXg+LIgj6sYMuUNgcOZcZQEuyUPLbsZEiEkbOsCQr/JqKxeAjNmeCKUOlVpxZuHfj8mCMT5h2fXeByDj1Ie5szCdjhuqLjnSvWu1uXAQrdtyjCTMolNWKhBsUa+L8s5agh37qhk7ZHu5B1IrzDLUxyZ89aXda+6Rp/AC/F3EDZKEreruBqzVzIgOEo92RbyGXju2I2ekSr/AqUT2JBO6rdE6OWSt/ibdXFRkRv/f7XASwqwVsFkBgnNBmioZLSOdIYw12ZcvotlFtNKfi2BMe6lj2ZY2DqA/rnnekaIPh2dBIrevzWQgLStqrn/2g59F2saBH6bg=");
           
            AsymmetricKeyParameter altPubDec = PqcPublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(altSubPubEnc));
            Assert.AreEqual(altEncKey, ((DilithiumPublicKeyParameters)altPubDec).GetEncoded());

            Security.SecureRandom random = new Security.SecureRandom();
            DilithiumKeyGenerationParameters kparam = new DilithiumKeyGenerationParameters(random, DilithiumParameters.Dilithium2Aes);
            DilithiumKeyPairGenerator kpg = new DilithiumKeyPairGenerator();
            kpg.Init(kparam);
            AsymmetricCipherKeyPair ackp = kpg.GenerateKeyPair();

            AsymmetricKeyParameter pub = ackp.Public;
            AsymmetricKeyParameter priv = ackp.Private;

            AsymmetricKeyParameter pubDec = PqcPublicKeyFactory.CreateKey(PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub));
            AsymmetricKeyParameter privDec = PqcPrivateKeyFactory.CreateKey(PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(priv));

            Assert.AreEqual(((DilithiumPublicKeyParameters)pub).GetEncoded(), ((DilithiumPublicKeyParameters)pubDec).GetEncoded());
            Assert.AreEqual(((DilithiumPrivateKeyParameters)priv).GetEncoded(), ((DilithiumPrivateKeyParameters)privDec).GetEncoded());
        }

        private static void RunTestVector(string name, IDictionary<string, string> buf)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);      // seed for SecureRandom
            int mlen = int.Parse(buf["mlen"]);          // message length
            byte[] msg = Hex.Decode(buf["msg"]);        // message
            byte[] pk = Hex.Decode(buf["pk"]);          // public key
            byte[] sk = Hex.Decode(buf["sk"]);          // private key
            int smlen = int.Parse(buf["smlen"]);        // signature length
            byte[] sm = Hex.Decode(buf["sm"]);          // signature

            NistSecureRandom random = new NistSecureRandom(seed, null);
            DilithiumParameters dilithiumparameters = Parameters[name];

            DilithiumKeyPairGenerator kpGen = new DilithiumKeyPairGenerator();
            DilithiumKeyGenerationParameters genParams =
                new DilithiumKeyGenerationParameters(random, dilithiumparameters);

            //
            // Generate keys and test.
            //
            kpGen.Init(genParams);
            AsymmetricCipherKeyPair ackp = kpGen.GenerateKeyPair();


            DilithiumPublicKeyParameters pubParams = (DilithiumPublicKeyParameters)ackp.Public;
            DilithiumPrivateKeyParameters privParams = (DilithiumPrivateKeyParameters)ackp.Private;

            //Console.WriteLine(string.Format("{0} Expected pk       = {1}", pk.Length, Convert.ToHexString(pk)));
            //Console.WriteLine(String.Format("{0} Actual Public key = {1}", pubParams.GetEncoded().Length, Convert.ToHexString(pubParams.GetEncoded())));

            pubParams = (DilithiumPublicKeyParameters)PqcPublicKeyFactory.CreateKey(PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(ackp.Public));
            privParams = (DilithiumPrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(ackp.Private));

            Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), name + " " + count + ": public key");
            Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), name + " " + count + ": secret key");

            //
            // Signature test
            //
            DilithiumSigner signer = new DilithiumSigner();
            DilithiumPrivateKeyParameters skparam = (DilithiumPrivateKeyParameters)ackp.Private;

            signer.Init(true, skparam);
            byte[] sigGenerated = signer.GenerateSignature(msg);
            byte[] attachedSig = Arrays.ConcatenateAll(sigGenerated, msg);

            //
            // Verify
            //
            DilithiumSigner verifier = new DilithiumSigner();
            DilithiumPublicKeyParameters pkparam = pubParams;
            verifier.Init(false, pkparam);
                
            bool vrfyrespass = verifier.VerifySignature(msg, sigGenerated);
            sigGenerated[3]++; // changing the signature by 1 byte should cause it to fail
            bool vrfyresfail = verifier.VerifySignature(msg, sigGenerated);
            
            Assert.True(Arrays.AreEqual(attachedSig, sm), name + " " + count + " signature");
            //verify
            Assert.True(vrfyrespass, name + " " + count + " verify failed when should pass");
            Assert.False(vrfyresfail, name + " " + count + " verify passed when should fail");
        }

        public static void RunTestVectorFile(string name)
        {
            var buf = new Dictionary<string, string>();
            TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.crystals.dilithium." + name)))
            {
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (line.StartsWith("#"))
                        continue;

                    if (line.Length > 0)
                    {
                        int a = line.IndexOf('=');
                        if (a > -1)
                        {
                            buf[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                        }
                        continue;
                    }

                    if (buf.Count > 0)
                    {
                        if (!sampler.SkipTest(buf["count"]))
                        {
                            RunTestVector(name, buf);
                        }
                        buf.Clear();
                    }
                }

                if (buf.Count > 0)
                {
                    if (!sampler.SkipTest(buf["count"]))
                    {
                        RunTestVector(name, buf);
                    }
                    buf.Clear();
                }
            }
        }
    }
}
