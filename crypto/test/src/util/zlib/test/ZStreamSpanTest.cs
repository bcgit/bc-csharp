using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Utilities.Zlib.Tests
{
    /// <summary>
    /// Tests for the <c>Read(Span)</c> / <c>Write(ReadOnlySpan)</c> overrides on <see cref="ZInputStream"/> and
    /// <see cref="ZOutputStream"/>, which route through the array overloads rather than the byte-at-a-time base
    /// implementations. The span and array paths must produce identical bytes.
    /// </summary>
    [TestFixture]
    public class ZStreamSpanTest
    {
        private const int FixedSeed = 0x2117;

        /// <summary>Sizes either side of the 4096-byte internal buffers, plus a few larger ones.</summary>
        private static readonly int[] Sizes = { 0, 1, 2, 100, 4095, 4096, 4097, 8191, 8192, 8193, 100000, 1000000 };

        /// <summary>Compressible data: long runs, so the deflater has something to do.</summary>
        private static byte[] CreateData(int length, int seed)
        {
            byte[] data = new byte[length];
            var rng = new Random(seed);
            int pos = 0;
            while (pos < length)
            {
                int runLength = System.Math.Min(rng.Next(1, 64), length - pos);
                byte value = (byte)rng.Next(0, 8);
                for (int i = 0; i < runLength; ++i)
                {
                    data[pos++] = value;
                }
            }
            return data;
        }

        private static byte[] CompressArray(byte[] data)
        {
            var output = new MemoryStream();
            using (var zOut = new ZOutputStreamLeaveOpen(output, JZlib.Z_BEST_COMPRESSION, nowrap: false))
            {
                zOut.Write(data, 0, data.Length);
            }
            return output.ToArray();
        }

        private static byte[] DecompressArray(byte[] compressed)
        {
            var output = new MemoryStream();
            using (var zIn = new ZInputStream(new MemoryStream(compressed, false)))
            {
                Streams.CopyTo(zIn, output);
            }
            return output.ToArray();
        }

        /*
         * NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly, which compiles
         * neither the overrides below nor those on BaseInputStream/BaseOutputStream. These tests then exercise the
         * runtime's own base implementations instead, which is still a worthwhile check that the span and array
         * paths agree.
         */
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Write the whole payload through <c>Write(ReadOnlySpan)</c> in one call.</summary>
        private static byte[] CompressSpan(byte[] data)
        {
            var output = new MemoryStream();
            using (var zOut = new ZOutputStreamLeaveOpen(output, JZlib.Z_BEST_COMPRESSION, nowrap: false))
            {
                zOut.Write(data.AsSpan());
            }
            return output.ToArray();
        }

        /// <summary>Read through <c>Read(Span)</c>, with the request size varying around the internal buffer.</summary>
        private static byte[] DecompressSpan(byte[] compressed, int seed, int maxRequest)
        {
            var output = new MemoryStream();
            using (var zIn = new ZInputStream(new MemoryStream(compressed, false)))
            {
                var rng = new Random(seed);
                byte[] scratch = new byte[maxRequest];
                for (;;)
                {
                    int request = rng.Next(1, maxRequest + 1);
                    int numRead = zIn.Read(scratch.AsSpan(0, request));
                    if (numRead < 1)
                        break;

                    Assert.LessOrEqual(numRead, request, "read more than requested");
                    output.Write(scratch, 0, numRead);
                }
            }
            return output.ToArray();
        }

        [Test]
        public void SpanWriteMatchesArrayWrite()
        {
            foreach (int size in Sizes)
            {
                byte[] data = CreateData(size, FixedSeed + size);

                Assert.IsTrue(Arrays.AreEqual(CompressArray(data), CompressSpan(data)),
                    $"compressed output differs at size {size}");
            }
        }

        [Test]
        public void SpanReadRoundTrips([Values(1, 64, 4096, 10000)] int maxRequest)
        {
            foreach (int size in Sizes)
            {
                byte[] data = CreateData(size, FixedSeed + size);
                byte[] compressed = CompressArray(data);

                Assert.IsTrue(Arrays.AreEqual(data, DecompressSpan(compressed, FixedSeed + size, maxRequest)),
                    $"round trip failed at size {size}, maxRequest {maxRequest}");
            }
        }

        [Test]
        public void SpanRoundTripsBothWays()
        {
            foreach (int size in Sizes)
            {
                byte[] data = CreateData(size, FixedSeed + size);

                Assert.IsTrue(Arrays.AreEqual(data, DecompressSpan(CompressSpan(data), FixedSeed, 4096)),
                    $"round trip failed at size {size}");
            }
        }

        /// <summary>
        /// An empty span must neither read nor write anything, and must not allocate a transfer buffer.
        /// </summary>
        [Test]
        public void EmptySpanIsNoOp()
        {
            byte[] data = CreateData(1000, FixedSeed);
            byte[] compressed = CompressArray(data);

            var output = new MemoryStream();
            using (var zOut = new ZOutputStreamLeaveOpen(output, JZlib.Z_BEST_COMPRESSION, nowrap: false))
            {
                zOut.Write(ReadOnlySpan<byte>.Empty);
                Assert.AreEqual(0, output.Length);
                zOut.Write(data.AsSpan());
            }
            Assert.IsTrue(Arrays.AreEqual(compressed, output.ToArray()));

            using (var zIn = new ZInputStream(new MemoryStream(compressed, false)))
            {
                Assert.AreEqual(0, zIn.Read(Span<byte>.Empty));
                Assert.IsTrue(Arrays.AreEqual(data, Streams.ReadAll(zIn)));
            }
        }

        /// <summary>At end of data the span read must report zero, repeatedly.</summary>
        [Test]
        public void SpanReadAtEndReturnsZero()
        {
            byte[] data = CreateData(5000, FixedSeed);
            byte[] compressed = CompressArray(data);

            using (var zIn = new ZInputStream(new MemoryStream(compressed, false)))
            {
                byte[] scratch = new byte[8192];
                int total = 0, numRead;
                while ((numRead = zIn.Read(scratch.AsSpan())) > 0)
                {
                    total += numRead;
                }

                Assert.AreEqual(data.Length, total);
                Assert.AreEqual(0, zIn.Read(scratch.AsSpan()));
                Assert.AreEqual(0, zIn.Read(scratch.AsSpan()));
            }
        }
#else
        [Test]
        public void ArrayRoundTripOnly()
        {
            // No span overrides on this target framework; check the array path still round trips.
            foreach (int size in Sizes)
            {
                byte[] data = CreateData(size, FixedSeed + size);

                Assert.IsTrue(Arrays.AreEqual(data, DecompressArray(CompressArray(data))),
                    $"round trip failed at size {size}");
            }
        }
#endif
    }
}
