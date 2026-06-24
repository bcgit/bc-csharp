using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X500.Style;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class IetfUtilitiesTest
    {
        [Test]
        public void ValueToString()
        {
            IetfUtilities.ValueToString(new DerUtf8String(" "));

            // RFC 4514 escaping - also a regression guard for the linear (non O(n^2)) valueToString.
            Assert.AreEqual("abc", IetfUtilities.ValueToString(new DerUtf8String("abc")), "plain");
            Assert.AreEqual("a\\,b", IetfUtilities.ValueToString(new DerUtf8String("a,b")), "comma");
            Assert.AreEqual("\\,\\\"\\\\\\+\\=\\<\\>\\;", IetfUtilities.ValueToString(new DerUtf8String(",\"\\+=<>;")),
                "all specials");
            Assert.AreEqual("\\ ab", IetfUtilities.ValueToString(new DerUtf8String(" ab")), "leading space");
            Assert.AreEqual("ab\\ ", IetfUtilities.ValueToString(new DerUtf8String("ab ")), "trailing space");
            Assert.AreEqual("\\ ab\\ ", IetfUtilities.ValueToString(new DerUtf8String(" ab ")),
                "leading+trailing space");
            Assert.AreEqual("\\ \\ \\ ", IetfUtilities.ValueToString(new DerUtf8String("   ")), "all spaces");
            Assert.AreEqual("a b", IetfUtilities.ValueToString(new DerUtf8String("a b")), "interior space kept");
            Assert.AreEqual("\\#abc", IetfUtilities.ValueToString(new DerUtf8String("#abc")), "leading hash");
            Assert.AreEqual("a#b", IetfUtilities.ValueToString(new DerUtf8String("a#b")), "non-leading hash kept");

            // A large all-special value must escape every character and complete in linear time (the
            // previous insert-into-the-buffer-being-scanned loop was O(n^2)).
            int n = 100000;
            StringBuilder commas = new StringBuilder(n);
            for (int i = 0; i < n; i++)
            {
                commas.Append(',');
            }
            string escaped = IetfUtilities.ValueToString(new DerUtf8String(commas.ToString()));
            Assert.AreEqual(2 * n, escaped.Length, "large all-comma value fully escaped");
        }
    }
}
