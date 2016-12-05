using System;
using System.Globalization;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Security.Tests
{
    [TestFixture]
    public class TestMacUtilities
    {
        [Test]
        public void TestCultureIndependence()
        {
            CultureInfo ci = CultureInfo.CurrentCulture;
            try
            {
                /*
                 * In Hungarian, the "CS" in "HMACSHA256" is linguistically a single character, so "HMAC" is not a prefix.
                 */
                CultureInfo.CurrentCulture = new CultureInfo("hu-HU");
                IMac mac = MacUtilities.GetMac("HMACSHA256");
                Assert.NotNull(mac);
            }
            catch (Exception e)
            {
                Assert.Fail("Culture-specific lookup failed: " + e.Message);
            }
            finally
            {
                CultureInfo.CurrentCulture = ci;
            }
        }
    }
}
