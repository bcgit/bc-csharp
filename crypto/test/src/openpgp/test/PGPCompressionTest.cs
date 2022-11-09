using System;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
	[TestFixture]
	public class PgpCompressionTest
		: SimpleTest
	{
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Data1 = new byte[0];
        private static readonly byte[] Data2 = Encoding.ASCII.GetBytes("hello world! !dlrow olleh");

        [Test]
        public void TestBZip2()
        {
            DoTestCompression(Data1, CompressionAlgorithmTag.BZip2);
            DoTestCompression(Data2, CompressionAlgorithmTag.BZip2);
            DoTestCompression(RandomData(1000000), CompressionAlgorithmTag.BZip2);
        }

        [Test]
		public void TestUncompressed()
		{
			DoTestCompression(Data1, CompressionAlgorithmTag.Uncompressed);
            DoTestCompression(Data2, CompressionAlgorithmTag.Uncompressed);
            DoTestCompression(RandomData(1000000), CompressionAlgorithmTag.Uncompressed);
        }

        [Test]
		public void TestZip()
		{
			DoTestCompression(Data1, CompressionAlgorithmTag.Zip);
            DoTestCompression(Data2, CompressionAlgorithmTag.Zip);
            DoTestCompression(RandomData(1000000), CompressionAlgorithmTag.Zip);
        }

        [Test]
		public void TestZLib()
		{
			DoTestCompression(Data1, CompressionAlgorithmTag.ZLib);
            DoTestCompression(Data2, CompressionAlgorithmTag.ZLib);
            DoTestCompression(RandomData(1000000), CompressionAlgorithmTag.ZLib);
        }

        public override void PerformTest()
		{
            TestBZip2();
            TestUncompressed();
            TestZip();
            TestZLib();
		}

		private void DoTestCompression(byte[] data, CompressionAlgorithmTag type)
		{
			DoTestCompression(data, type, true);
			DoTestCompression(data, type, false);
		}

		private void DoTestCompression(byte[] data, CompressionAlgorithmTag	type, bool streamClose)
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
				cPacket.Dispose();
			}

			ValidateData(data, bOut.ToArray());

			try
			{
				os.Dispose();
				cPacket.Dispose();
			}
			catch (Exception)
			{
				Fail("Redundant Close() should be ignored");
			}
		}

        private byte[] RandomData(int length)
        {
            return SecureRandom.GetNextBytes(Random, length);
        }

		private void ValidateData(byte[] data, byte[] compressed)
		{
			PgpObjectFactory pgpFact = new PgpObjectFactory(compressed);
			PgpCompressedData c1 = (PgpCompressedData) pgpFact.NextPgpObject();

			Stream pIn = c1.GetDataStream();
			byte[] bytes = Streams.ReadAll(pIn);
			pIn.Close();

			if (!AreEqual(bytes, data))
			{
				Fail("compression test failed");
			}
		}

		public override string Name
		{
			get { return "PgpCompressionTest"; }
		}
	}
}
