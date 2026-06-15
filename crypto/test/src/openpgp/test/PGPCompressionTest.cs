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
            ImplTestCompression(Data1, CompressionAlgorithmTag.BZip2);
            ImplTestCompression(Data2, CompressionAlgorithmTag.BZip2);
            ImplTestCompression(RandomData(1000000), CompressionAlgorithmTag.BZip2);
        }

        [Test]
        public void TestUncompressed()
        {
            ImplTestCompression(Data1, CompressionAlgorithmTag.Uncompressed);
            ImplTestCompression(Data2, CompressionAlgorithmTag.Uncompressed);
            ImplTestCompression(RandomData(1000000), CompressionAlgorithmTag.Uncompressed);
        }

        [Test]
        public void TestZip()
        {
            ImplTestCompression(Data1, CompressionAlgorithmTag.Zip);
            ImplTestCompression(Data2, CompressionAlgorithmTag.Zip);
            ImplTestCompression(RandomData(1000000), CompressionAlgorithmTag.Zip);
        }

        [Test]
        public void TestZLib()
        {
            ImplTestCompression(Data1, CompressionAlgorithmTag.ZLib);
            ImplTestCompression(Data2, CompressionAlgorithmTag.ZLib);
            ImplTestCompression(RandomData(1000000), CompressionAlgorithmTag.ZLib);
        }

        private static void ImplTestCompression(byte[] data, CompressionAlgorithmTag type)
        {
            ImplTestCompression(data, type, true);
            ImplTestCompression(data, type, false);
        }

        private static void ImplTestCompression(byte[] data, CompressionAlgorithmTag type, bool streamClose)
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
    }
}
