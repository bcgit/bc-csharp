using NUnit.Framework;

namespace Org.BouncyCastle.Utilities.UtilTests
{
    [TestFixture]
    public class StringsTest
    {
        [Test]
        public void SplitConsecutiveDelimiters() => CheckSplit("a..b", '.', "a", "", "b");

        [Test]
        public void SplitDomainWithLeadingDot() =>
            CheckSplit(".example.domain.com", '.', "", "example", "domain", "com");

        [Test]
        public void SplitLeadingDelimiter() => CheckSplit(".permitted", '.', "", "permitted");

        [Test]
        public void SplitNoDelimiters() => CheckSplit("nodots", '.', "nodots");

        [Test]
        public void SplitNormalDomain() => CheckSplit("example.domain.com", '.', "example", "domain", "com");

        [Test]
        public void SplitOnlyDelimiter() => CheckSplit(".", '.', "", "");

        [Test]
        public void SplitTrailingDelimiter() => CheckSplit("trailing.", '.', "trailing", "");

        private static void CheckSplit(string input, char delimiter, params string[] expected) =>
            Assert.AreEqual(expected, Strings.Split(input, delimiter));
    }
}
