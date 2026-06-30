using System;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    [NonParallelizable] // Environment.SetEnvironmentVariable
    public class StreamLimitTest
    {
        [Test]
        public void ConfigureMaxLimitViaEnvironment()
        {
            // TODO bc-java supports suffixed like so:
            // 1024k => 1048576
            // 1024m => 1073741824
            // 1g => 1073741824

            SetMaxLimitProperty(1024);
            CheckLimit(1024);

            ClearMaxLimitProperty();
            CheckLimit(Arrays.MaxLength);
        }

        [Test]
        public void ConfigureMaxLimitViaProperties()
        {
            // TODO bc-java supports suffixed like so:
            // 1024k => 1048576
            // 1024m => 1073741824
            // 1g => 1073741824

            CheckLimit(Arrays.MaxLength);

            Properties.WithThreadProperty(Asn1InputStream.MaxLimitProperty, "1024", () =>
            {
                CheckLimit(1024);
            });

            CheckLimit(Arrays.MaxLength);

            Properties.SetThreadInt32(Asn1InputStream.MaxLimitProperty, 2048);

            CheckLimit(2048);

            Properties.WithThreadProperty(Asn1InputStream.MaxLimitProperty, "3072", () =>
            {
                CheckLimit(3072);
            });

            CheckLimit(2048);

            Properties.RemoveThreadProperty(Asn1InputStream.MaxLimitProperty);

            CheckLimit(Arrays.MaxLength);
        }

        private static void CheckLimit(int expected)
        {
            var asn1 = new Asn1InputStream(new MyStream());
            Assert.AreEqual(expected, asn1.Limit);
        }

        private static void ClearMaxLimitProperty() => SetMaxLimitProperty(null);

        private static void SetMaxLimitProperty(int value) => SetMaxLimitProperty(value.ToString());

        private static void SetMaxLimitProperty(string value) =>
            Environment.SetEnvironmentVariable(Asn1InputStream.MaxLimitProperty, value);

        private class MyStream : BaseInputStream
        {
            public override int ReadByte() => -1;
        }
    }
}
