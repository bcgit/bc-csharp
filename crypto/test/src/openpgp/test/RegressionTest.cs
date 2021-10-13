using System;

using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    public class RegressionTest
    {
        public static ITest[] tests =
        {
            new ArmoredInputStreamTest(),
            new IgnoreMarkerPacketInCertificatesTest(),
            new PgpArmoredTest(),
            new PgpClearSignedSignatureTest(),
            new PgpCompressionTest(),
            new PgpDsaElGamalTest(),
            new PgpDsaTest(),
            new PgpECDHTest(),
            new PgpECDsaTest(),
            new PgpECMessageTest(),
            new PgpFeaturesTest(),
            new PgpKeyRingTest(),
            new PgpMarkerTest(),
            new PgpNoPrivateKeyTest(),
            new PgpPacketTest(),
            new PgpParsingTest(),
            new PgpPbeTest(),
            new PgpRsaTest(),
            new PgpSignatureInvalidVersionIgnoredTest(),
            new PgpSignatureTest(),
        };

        public static void Main(string[] args)
        {
            foreach (ITest test in tests)
            {
                SimpleTest.RunTest(test);
            }
        }
    }
}
