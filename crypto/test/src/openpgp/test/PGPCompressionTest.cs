using System;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpCompressionTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Data1 = new byte[0];
        private static readonly byte[] Data2 = Encoding.ASCII.GetBytes("hello world! !dlrow olleh");

        [Test]
        public void TestBZip2()
        {
            CheckCompression(Data1, CompressionAlgorithmTag.BZip2);
            CheckCompression(Data2, CompressionAlgorithmTag.BZip2);
            CheckCompression(RandomData(1000000), CompressionAlgorithmTag.BZip2);
        }

        [Test]
        public void TestUncompressed()
        {
            CheckCompression(Data1, CompressionAlgorithmTag.Uncompressed);
            CheckCompression(Data2, CompressionAlgorithmTag.Uncompressed);
            CheckCompression(RandomData(1000000), CompressionAlgorithmTag.Uncompressed);
        }

        [Test]
        public void TestZip()
        {
            CheckCompression(Data1, CompressionAlgorithmTag.Zip);
            CheckCompression(Data2, CompressionAlgorithmTag.Zip);
            CheckCompression(RandomData(1000000), CompressionAlgorithmTag.Zip);
        }

        [Test]
        public void TestZLib()
        {
            CheckCompression(Data1, CompressionAlgorithmTag.ZLib);
            CheckCompression(Data2, CompressionAlgorithmTag.ZLib);
            CheckCompression(RandomData(1000000), CompressionAlgorithmTag.ZLib);
        }

        private static void CheckCompression(byte[] data, CompressionAlgorithmTag type)
        {
            CheckCompression(data, type, streamClose: true);
            CheckCompression(data, type, streamClose: false);
        }

        private static void CheckCompression(byte[] data, CompressionAlgorithmTag type, bool streamClose)
        {
            MemoryStream bOut = new MemoryStream();
            PgpCompressedDataGenerator cPacket = new PgpCompressedDataGenerator(type);
            Stream os = cPacket.Open(new UncloseableStream(bOut));
            os.Write(data, 0, data.Length);

            if (streamClose)
            {
                os.Dispose();
            }
            else
            {
#pragma warning disable CS0618 // Type or member is obsolete
                cPacket.Close();
#pragma warning restore CS0618 // Type or member is obsolete
            }

            ValidateData(data, bOut.ToArray());

            try
            {
                os.Dispose();
#pragma warning disable CS0618 // Type or member is obsolete
                cPacket.Close();
#pragma warning restore CS0618 // Type or member is obsolete
            }
            catch (Exception)
            {
                Assert.Fail("Redundant Close() should be ignored");
            }
        }

        private static byte[] RandomData(int length) => SecureRandom.GetNextBytes(Random, length);

        private static void ValidateData(byte[] data, byte[] compressed)
        {
            PgpObjectFactory pgpFact = new PgpObjectFactory(compressed);
            PgpCompressedData c1 = (PgpCompressedData)pgpFact.NextPgpObject();

            byte[] bytes;
            using (var pIn = c1.GetDataStream())
            {
                bytes = Streams.ReadAll(pIn);
            }

            Assert.That(Arrays.AreEqual(data, bytes), "compression test failed");
        }

        [Test]
        public void DecompressionLimit()
        {
            byte[] data = RandomData(64 * 1024);

            CheckDecompressionLimit(data, CompressionAlgorithmTag.Uncompressed);
            CheckDecompressionLimit(data, CompressionAlgorithmTag.Zip);
            CheckDecompressionLimit(data, CompressionAlgorithmTag.ZLib);
            CheckDecompressionLimit(data, CompressionAlgorithmTag.BZip2);
        }

        private static void CheckDecompressionLimit(byte[] data, CompressionAlgorithmTag type)
        {
            MemoryStream bOut = new MemoryStream();
            PgpCompressedDataGenerator cPacket = new PgpCompressedDataGenerator(type);

            using (var os = cPacket.Open(new UncloseableStream(bOut)))
            {
                os.Write(data, 0, data.Length);
            }

            byte[] packet = bOut.ToArray();

            // a limit at least the size of the data lets the full content through
            PgpCompressedData c1 = (PgpCompressedData)new PgpObjectFactory(packet).NextPgpObject();

            Assert.That(Arrays.AreEqual(data, Streams.ReadAll(c1.GetDataStream(data.Length))),
                "limit >= data should round-trip for type " + type);

            // a limit one short of the data fails with StreamOverflowException
            PgpCompressedData c2 = (PgpCompressedData)new PgpObjectFactory(packet).NextPgpObject();

            using (var limited = c2.GetDataStream(data.Length - 1))
            {
                try
                {
                    Streams.ReadAll(limited);
                    Assert.Fail("decompressed data limit not enforced for type " + type);
                }
                catch (StreamOverflowException)
                {
                    // expected
                }
            }

            // a negative limit is equivalent to the unbounded getDataStream()
            PgpCompressedData c3 = (PgpCompressedData)new PgpObjectFactory(packet).NextPgpObject();

            Assert.That(Arrays.AreEqual(data, Streams.ReadAll(c3.GetDataStream(-1))),
                "negative limit should be unbounded for type " + type);
        }
    }
}
