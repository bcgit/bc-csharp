using NUnit.Framework;

namespace Org.BouncyCastle.Utilities.UtilTests
{
    [TestFixture]
    public class StringsTest
    {
        [Test]
        public void SplitWithLeadingDelimiter()
        {
            string[] parts = Strings.Split(".permitted", '.');
            Assert.AreEqual(2, parts.Length);
            Assert.AreEqual("", parts[0]);
            Assert.AreEqual("permitted", parts[1]);
        }

        [Test]
        public void SplitDomainWithLeadingDot()
        {
            string[] parts = Strings.Split(".example.domain.com", '.');
            Assert.AreEqual(4, parts.Length);
            Assert.AreEqual("", parts[0]);
            Assert.AreEqual("example", parts[1]);
            Assert.AreEqual("domain", parts[2]);
            Assert.AreEqual("com", parts[3]);
        }

        [Test]
        public void SplitNormalDomain()
        {
            string[] parts = Strings.Split("example.domain.com", '.');
            Assert.AreEqual(3, parts.Length);
            Assert.AreEqual("example", parts[0]);
            Assert.AreEqual("domain", parts[1]);
            Assert.AreEqual("com", parts[2]);
        }

        [Test]
        public void SplitNoDelimiter()
        {
            string[] parts = Strings.Split("nodots", '.');
            Assert.AreEqual(1, parts.Length);
            Assert.AreEqual("nodots", parts[0]);
        }

        [Test]
        public void SplitTrailingDelimiter()
        {
            string[] parts = Strings.Split("trailing.", '.');
            Assert.AreEqual(2, parts.Length);
            Assert.AreEqual("trailing", parts[0]);
            Assert.AreEqual("", parts[1]);
        }

        [Test]
        public void SplitOnlyDelimiter()
        {
            string[] parts = Strings.Split(".", '.');
            Assert.AreEqual(2, parts.Length);
            Assert.AreEqual("", parts[0]);
            Assert.AreEqual("", parts[1]);
        }

        [Test]
        public void SplitConsecutiveDelimiters()
        {
            string[] parts = Strings.Split("a..b", '.');
            Assert.AreEqual(3, parts.Length);
            Assert.AreEqual("a", parts[0]);
            Assert.AreEqual("", parts[1]);
            Assert.AreEqual("b", parts[2]);
        }
    }
}
