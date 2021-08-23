using System;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class ByteQueueInputStreamTest
    {
        [Test]
        public void TestAvailable()
        {
            ByteQueueInputStream input = new ByteQueueInputStream();

            // buffer is empty
            Assert.AreEqual(0, input.Available);

            // after adding once
            input.AddBytes(new byte[10]);
            Assert.AreEqual(10, input.Available);

            // after adding more than once
            input.AddBytes(new byte[5]);
            Assert.AreEqual(15, input.Available);

            // after reading a single byte
            input.ReadByte();
            Assert.AreEqual(14, input.Available);

            // after reading into a byte array
            input.Read(new byte[4], 0, 4);
            Assert.AreEqual(10, input.Available);

            input.Close();
        }

        [Test]
        public void TestSkip()
        {
            ByteQueueInputStream input = new ByteQueueInputStream();

            // skip when buffer is empty
            Assert.AreEqual(0, input.Skip(10));

            // skip equal to available
            input.AddBytes(new byte[2]);
            Assert.AreEqual(2, input.Skip(2));
            Assert.AreEqual(0, input.Available);

            // skip less than available
            input.AddBytes(new byte[10]);
            Assert.AreEqual(5, input.Skip(5));
            Assert.AreEqual(5, input.Available);

            // skip more than available
            Assert.AreEqual(5, input.Skip(20));
            Assert.AreEqual(0, input.Available);

            input.Close();
        }

        [Test]
        public void TestRead()
        {
            ByteQueueInputStream input = new ByteQueueInputStream();
            input.AddBytes(new byte[]{ 0x01, 0x02 });
            input.AddBytes(new byte[]{ 0x03 });

            Assert.AreEqual(0x01, input.ReadByte());
            Assert.AreEqual(0x02, input.ReadByte());
            Assert.AreEqual(0x03, input.ReadByte());
            Assert.AreEqual(-1, input.ReadByte());

            input.Close();
        }

        [Test]
        public void TestReadArray()
        {
            ByteQueueInputStream input = new ByteQueueInputStream();
            input.AddBytes(new byte[]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 });

            byte[] buffer = new byte[5];

            // read less than available into specified position
            Assert.AreEqual(1, input.Read(buffer, 2, 1));
            AssertArrayEquals(new byte[]{ 0x00, 0x00, 0x01, 0x00, 0x00 }, buffer);

            // read equal to available
            Assert.AreEqual(5, input.Read(buffer, 0, buffer.Length));
            AssertArrayEquals(new byte[]{ 0x02, 0x03, 0x04, 0x05, 0x06 }, buffer);

            // read more than available
            input.AddBytes(new byte[]{ 0x01, 0x02, 0x03 });
            Assert.AreEqual(3, input.Read(buffer, 0, buffer.Length));
            AssertArrayEquals(new byte[]{ 0x01, 0x02, 0x03, 0x05, 0x06 }, buffer);

            input.Close();
        }

        [Test]
        public void TestPeek()
        {
            ByteQueueInputStream input = new ByteQueueInputStream();

            byte[] buffer = new byte[5];

            // peek more than available
            Assert.AreEqual(0, input.Peek(buffer));
            AssertArrayEquals(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00 }, buffer);

            // peek less than available
            input.AddBytes(new byte[]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 });
            Assert.AreEqual(5, input.Peek(buffer));
            AssertArrayEquals(new byte[]{ 0x01, 0x02, 0x03, 0x04, 0x05 }, buffer);
            Assert.AreEqual(6, input.Available);

            // peek equal to available
            input.ReadByte();
            Assert.AreEqual(5, input.Peek(buffer));
            AssertArrayEquals(new byte[]{ 0x02, 0x03, 0x04, 0x05, 0x06 }, buffer);
            Assert.AreEqual(5, input.Available);

            input.Close();
        }

        private static void AssertArrayEquals(byte[] a, byte[] b)
        {
            Assert.IsTrue(Arrays.AreEqual(a, b));
        }
    }
}
