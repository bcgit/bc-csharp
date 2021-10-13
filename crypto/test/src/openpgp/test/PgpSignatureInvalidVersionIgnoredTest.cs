using System;
using System.Collections;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpSignatureInvalidVersionIgnoredTest
        : SimpleTest
    {
        // Signing Key ID
        private static readonly long KEY_ID = new BigInteger("FBFCC82A015E7330", 16).LongValue;

        // Signature List consisting of Version 4 Signature and Version 23 (invalid version) Signature
        private static readonly string SIG4SIG23 = "-----BEGIN PGP SIGNATURE-----\n" +
            "\n" +
            "wsE7BAABCgBvBYJgyf2fCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
            "cy5zZXF1b2lhLXBncC5vcmdURSYEGurWv1IDN4trcpgfrHMZeGRdhG5jlQazr8tJ\n" +
            "QRYhBNGmbhojsYLJmA94jPv8yCoBXnMwAADAYwv+NeSzVRrR/CGLMna43b0xCrOz\n" +
            "tEYVp3hLzjCYWP1F5d7OdrpQWB3jzgMhjkH5ZnSm369A6D6eEoo05uP7lUNoex7s\n" +
            "Bcksq4QF2t9y0YHwjhciVyPUw0rgzOIDpJ6jb/HqEgWB+EYz5qU3RFAk4tz+ghpw\n" +
            "93x+EAI7QBnw+PRjgmJiXQvcq78W+h8aysAQCv/dNJc9W8gfCpwDY2VKTc0BW9VI\n" +
            "R4KbeI2Rgx378JYjzJNP9ORgDTacBdQh3LiqJ8B4x7OeVGouGbWEVG6x+htQ9YMH\n" +
            "uOY1CmcNzoMSRyk50JOeM0Xcge/9PLuQM+b4OQ3ZRN/BhUEg4P/VclXzkWeDKCvP\n" +
            "cGEUrdFnyU1Lk2mYh1HTKS3gurTP9bdAyS9sdjXj9kv2fRM5N46rBRAffjwfW/LT\n" +
            "VedvgRZ3RMCLrwPo90ID/xVU8PC9VmBR+WrqOijdsgnh7n940NR5hSyeWVeMwNFl\n" +
            "Js043gKSIc5yNLS16mE/YzgosnUpIUsDlSR6D8M/wsE7FwABCgBvBYJgyf2fCRD7\n" +
            "/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmdU\n" +
            "RSYEGurWv1IDN4trcpgfrHMZeGRdhG5jlQazr8tJQRYhBNGmbhojsYLJmA94jPv8\n" +
            "yCoBXnMwAADAYwv+NeSzVRrR/CGLMna43b0xCrOztEYVp3hLzjCYWP1F5d7OdrpQ\n" +
            "WB3jzgMhjkH5ZnSm369A6D6eEoo05uP7lUNoex7sBcksq4QF2t9y0YHwjhciVyPU\n" +
            "w0rgzOIDpJ6jb/HqEgWB+EYz5qU3RFAk4tz+ghpw93x+EAI7QBnw+PRjgmJiXQvc\n" +
            "q78W+h8aysAQCv/dNJc9W8gfCpwDY2VKTc0BW9VIR4KbeI2Rgx378JYjzJNP9ORg\n" +
            "DTacBdQh3LiqJ8B4x7OeVGouGbWEVG6x+htQ9YMHuOY1CmcNzoMSRyk50JOeM0Xc\n" +
            "ge/9PLuQM+b4OQ3ZRN/BhUEg4P/VclXzkWeDKCvPcGEUrdFnyU1Lk2mYh1HTKS3g\n" +
            "urTP9bdAyS9sdjXj9kv2fRM5N46rBRAffjwfW/LTVedvgRZ3RMCLrwPo90ID/xVU\n" +
            "8PC9VmBR+WrqOijdsgnh7n940NR5hSyeWVeMwNFlJs043gKSIc5yNLS16mE/Yzgo\n" +
            "snUpIUsDlSR6D8M/\n" +
            "=Ptch\n" +
            "-----END PGP SIGNATURE-----";

        // Signature List consisting of Version 23 (invalid version) Signature and Version 4 Signature
        private static readonly string SIG23SIG4 = "-----BEGIN PGP SIGNATURE-----\n" +
            "\n" +
            "wsE7FwABCgBvBYJgyf2fCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
            "cy5zZXF1b2lhLXBncC5vcmdURSYEGurWv1IDN4trcpgfrHMZeGRdhG5jlQazr8tJ\n" +
            "QRYhBNGmbhojsYLJmA94jPv8yCoBXnMwAADAYwv+NeSzVRrR/CGLMna43b0xCrOz\n" +
            "tEYVp3hLzjCYWP1F5d7OdrpQWB3jzgMhjkH5ZnSm369A6D6eEoo05uP7lUNoex7s\n" +
            "Bcksq4QF2t9y0YHwjhciVyPUw0rgzOIDpJ6jb/HqEgWB+EYz5qU3RFAk4tz+ghpw\n" +
            "93x+EAI7QBnw+PRjgmJiXQvcq78W+h8aysAQCv/dNJc9W8gfCpwDY2VKTc0BW9VI\n" +
            "R4KbeI2Rgx378JYjzJNP9ORgDTacBdQh3LiqJ8B4x7OeVGouGbWEVG6x+htQ9YMH\n" +
            "uOY1CmcNzoMSRyk50JOeM0Xcge/9PLuQM+b4OQ3ZRN/BhUEg4P/VclXzkWeDKCvP\n" +
            "cGEUrdFnyU1Lk2mYh1HTKS3gurTP9bdAyS9sdjXj9kv2fRM5N46rBRAffjwfW/LT\n" +
            "VedvgRZ3RMCLrwPo90ID/xVU8PC9VmBR+WrqOijdsgnh7n940NR5hSyeWVeMwNFl\n" +
            "Js043gKSIc5yNLS16mE/YzgosnUpIUsDlSR6D8M/wsE7BAABCgBvBYJgyf2fCRD7\n" +
            "/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmdU\n" +
            "RSYEGurWv1IDN4trcpgfrHMZeGRdhG5jlQazr8tJQRYhBNGmbhojsYLJmA94jPv8\n" +
            "yCoBXnMwAADAYwv+NeSzVRrR/CGLMna43b0xCrOztEYVp3hLzjCYWP1F5d7OdrpQ\n" +
            "WB3jzgMhjkH5ZnSm369A6D6eEoo05uP7lUNoex7sBcksq4QF2t9y0YHwjhciVyPU\n" +
            "w0rgzOIDpJ6jb/HqEgWB+EYz5qU3RFAk4tz+ghpw93x+EAI7QBnw+PRjgmJiXQvc\n" +
            "q78W+h8aysAQCv/dNJc9W8gfCpwDY2VKTc0BW9VIR4KbeI2Rgx378JYjzJNP9ORg\n" +
            "DTacBdQh3LiqJ8B4x7OeVGouGbWEVG6x+htQ9YMHuOY1CmcNzoMSRyk50JOeM0Xc\n" +
            "ge/9PLuQM+b4OQ3ZRN/BhUEg4P/VclXzkWeDKCvPcGEUrdFnyU1Lk2mYh1HTKS3g\n" +
            "urTP9bdAyS9sdjXj9kv2fRM5N46rBRAffjwfW/LTVedvgRZ3RMCLrwPo90ID/xVU\n" +
            "8PC9VmBR+WrqOijdsgnh7n940NR5hSyeWVeMwNFlJs043gKSIc5yNLS16mE/Yzgo\n" +
            "snUpIUsDlSR6D8M/\n" +
            "=o4rJ\n" +
            "-----END PGP SIGNATURE-----";

        public override string Name
        {
            get { return "PgpSignatureInvalidVersionIgnoredTest"; }
        }

        public override void PerformTest()
        {
            AssertInvalidSignatureVersionIsIgnored(SIG4SIG23);
            AssertInvalidSignatureVersionIsIgnored(SIG23SIG4);
        }

        public static void Main(string[] args)
        {
            RunTest(new PgpSignatureInvalidVersionIgnoredTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }

        private void AssertInvalidSignatureVersionIsIgnored(string sig)
        {
            ArmoredInputStream armorIn = new ArmoredInputStream(
                new MemoryStream(Encoding.UTF8.GetBytes(sig), false));
            PgpObjectFactory objectFactory = new PgpObjectFactory(armorIn);
            PgpSignatureList signatures = (PgpSignatureList)objectFactory.NextPgpObject();
            IsEquals(1, signatures.Count);
            PgpSignature signature = signatures[0];
            IsEquals(KEY_ID, signature.KeyId);
        }
    }
}
