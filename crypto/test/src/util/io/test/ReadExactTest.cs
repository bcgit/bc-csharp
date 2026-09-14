using System;
using System.Collections.Generic;
using System.Diagnostics;

using NUnit.Framework;

namespace Org.BouncyCastle.Utilities.IO.Tests
{
    /// <summary>
    /// Correctness tests and an <c>[Explicit]</c> benchmark (run with <c>--filter Bench_</c>) for the exact-length
    /// incremental reader in <see cref="Streams"/>.
    /// </summary>
    [TestFixture]
    public class ReadExactTest
    {
        public enum SourceMode
        {
            /// <summary>Serves the whole request in one Read (MemoryStream-like).</summary>
            Full,
            /// <summary>Serves a random 1..16 KiB per Read (network-like).</summary>
            Chunky,
            /// <summary>Serves a random 1..3 bytes per Read (worst case for the fill loop).</summary>
            Trickle,
        }

        private const int FixedSeed = 0x5EED;
        private const int DataSize = 1 << 24;
        private const int ChunkyMaxRead = 1 << 14;
        private const int TrickleMaxRead = 3;

        private static byte[] s_data;

        [OneTimeSetUp]
        public void Init()
        {
            s_data = new byte[DataSize];
            new Random(FixedSeed).NextBytes(s_data);
        }

        /// <summary>
        /// Serves a prefix of a byte array through <see cref="IReadSource"/>, at most <c>maxRead</c> bytes per call
        /// (a random 1..maxRead when seeded). A class so that the position survives the by-value struct adapter.
        /// </summary>
        private sealed class SegmentedReader
        {
            private readonly byte[] m_data;
            private readonly int m_maxRead;
            private int m_limit;
            private int m_pos;
            private Random m_rng;

            internal SegmentedReader(byte[] data, int maxRead)
            {
                m_data = data;
                m_maxRead = maxRead;
            }

            internal void Reset(int limit, int seed)
            {
                m_limit = limit;
                m_pos = 0;
                m_rng = m_maxRead > 0 ? new Random(seed) : null;
            }

            internal int Read(byte[] buffer, int offset, int count)
            {
                int avail = m_limit - m_pos;
                if (avail <= 0)
                    return 0;

                int n = System.Math.Min(count, avail);
                if (m_rng != null)
                {
                    n = System.Math.Min(n, m_rng.Next(1, m_maxRead + 1));
                }

                Array.Copy(m_data, m_pos, buffer, offset, n);
                m_pos += n;
                return n;
            }
        }

        private readonly struct SegmentedSource
            : IReadSource
        {
            private readonly SegmentedReader m_reader;

            internal SegmentedSource(SegmentedReader reader)
            {
                m_reader = reader;
            }

            public int Read(byte[] buffer, int offset, int count) => m_reader.Read(buffer, offset, count);
        }

        private static SegmentedReader CreateReader(SourceMode mode)
        {
            switch (mode)
            {
            case SourceMode.Full:
                return new SegmentedReader(s_data, 0);
            case SourceMode.Chunky:
                return new SegmentedReader(s_data, ChunkyMaxRead);
            case SourceMode.Trickle:
                return new SegmentedReader(s_data, TrickleMaxRead);
            default:
                throw new ArgumentOutOfRangeException(nameof(mode));
            }
        }

        // Boundaries of the reader (direct read up to two 64 KiB chunks; above that, chunk multiples and sizes whose
        // quarter is a chunk multiple, e.g. 256K, 512K), their neighbours, and some arbitrary sizes.
        private static readonly int[] EdgeSizes =
        {
            0, 1, 2, 3, 4095, 4096, 4097, 65535, 65536, 65537, 131071, 131072, 131073, 262143, 262144, 262145,
            327679, 327680, 327681, 524287, 524288, 524289, 1000003, (1 << 22) + 12345, (1 << 24) - 1, 1 << 24,
        };

        private static IEnumerable<int> TestSizes()
        {
            foreach (int size in EdgeSizes)
            {
                yield return size;
            }

            var rng = new Random(FixedSeed);
            for (int i = 0; i < 12; ++i)
            {
                yield return rng.Next(0, 1 << 21);
            }
        }

        [Test]
        public void ReadsExactLength([Values] SourceMode mode)
        {
            var reader = CreateReader(mode);
            var source = new SegmentedSource(reader);

            foreach (int size in TestSizes())
            {
                // Trickle mode is slow at large sizes and exercises nothing new there.
                if (mode == SourceMode.Trickle && size > 300000)
                    continue;

                reader.Reset(size, FixedSeed ^ size);

                Assert.IsTrue(Streams.TryReadExactIncremental(source, size, out byte[] bytes), $"{mode} size {size}");
                Assert.AreEqual(size, bytes.Length, $"{mode} size {size}");
                Assert.IsTrue(Arrays.AreEqual(s_data, 0, size, bytes, 0, size), $"{mode} size {size} contents");

                // The source must have been asked for exactly the data and nothing more.
                Assert.AreEqual(0, reader.Read(new byte[1], 0, 1), $"{mode} size {size} over-read");
            }
        }

        [Test]
        public void ShortInputReturnsFalse([Values(SourceMode.Full, SourceMode.Chunky)] SourceMode mode)
        {
            var reader = CreateReader(mode);
            var source = new SegmentedSource(reader);

            foreach (int size in TestSizes())
            {
                if (size == 0)
                    continue;

                foreach (int shortfall in new[] { 1, 4096, 65536, size / 2, size - 1, size })
                {
                    int limit = size - shortfall;
                    if (shortfall < 1 || limit < 0)
                        continue;

                    reader.Reset(limit, FixedSeed ^ size);

                    Assert.IsFalse(Streams.TryReadExactIncremental(source, size, out byte[] bytes),
                        $"{mode} size {size} limit {limit}");
                    Assert.IsNull(bytes);
                }
            }
        }

        [Test]
        public void InvalidLengthThrows()
        {
            var reader = CreateReader(SourceMode.Full);
            var source = new SegmentedSource(reader);
            reader.Reset(DataSize, 0);

            Assert.Throws<ArgumentOutOfRangeException>(() => Streams.TryReadExactIncremental(source, -1, out _));
            Assert.Throws<ArgumentOutOfRangeException>(
                () => Streams.TryReadExactIncremental(source, int.MinValue, out _));
            Assert.Throws<ArgumentOutOfRangeException>(
                () => Streams.TryReadExactIncremental(source, int.MaxValue, out _));
        }

        // ----- Benchmark (run with --filter Bench_) -----

        private const int BenchSizesPerClass = 64;
        private const int BenchPassBudgetMs = 1000;

        /// <summary>
        /// Sizes uniform in [2^log2Min, 2^(log2Min+1)]. Reports the median of three passes; on .NET Core also the
        /// allocated bytes per op as a multiple of the mean size (expected 1.00x up to 128 KiB, 1.25x above).
        /// </summary>
        [Test, Explicit]
        public void Bench_ReadExact([Values(SourceMode.Full, SourceMode.Chunky)] SourceMode mode,
            [Values(12, 16, 20, 23)] int log2Min)
        {
            int lo = 1 << log2Min, hi = 1 << (log2Min + 1);
            var rng = new Random(FixedSeed + log2Min);
            int[] sizes = new int[BenchSizesPerClass];
            long totalBytes = 0;
            for (int i = 0; i < sizes.Length; ++i)
            {
                sizes[i] = rng.Next(lo, hi + 1);
                totalBytes += sizes[i];
            }

            var reader = CreateReader(mode);
            var source = new SegmentedSource(reader);

            // Warm-up.
            RunSizes(reader, source, sizes);

            var results = new double[3];
            long allocPerOp = 0;
            for (int pass = 0; pass < 3; ++pass)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();

                long iters = 0;
#if NETCOREAPP3_0_OR_GREATER
                long allocBefore = GC.GetTotalAllocatedBytes(true);
#endif
                var sw = Stopwatch.StartNew();
                while (sw.Elapsed.TotalMilliseconds < BenchPassBudgetMs)
                {
                    RunSizes(reader, source, sizes);
                    iters += sizes.Length;
                }
                sw.Stop();
#if NETCOREAPP3_0_OR_GREATER
                allocPerOp = (GC.GetTotalAllocatedBytes(true) - allocBefore) / iters;
#endif

                results[pass] = sw.Elapsed.TotalMilliseconds * 1000.0 / iters;
            }

            double avgSize = (double)totalBytes / sizes.Length;
            double usPerOp = Median3(results[0], results[1], results[2]);
            double mbPerSec = avgSize / usPerOp;
            string alloc = allocPerOp > 0 ? $", {allocPerOp / avgSize:F2}x alloc" : "";
            TestContext.WriteLine(
                $"{mode} source, sizes in [{lo:N0}, {hi:N0}], mean {avgSize:N0} bytes: {usPerOp:N1} us/op"
                + $" {mbPerSec:N0} MB/s{alloc}");
            TestContext.WriteLine($"READEXACT_CSV,{mode},{log2Min},{usPerOp:F1},{mbPerSec:F0},{allocPerOp}");
        }

        private static void RunSizes(SegmentedReader reader, SegmentedSource source, int[] sizes)
        {
            foreach (int size in sizes)
            {
                // Same seed per size so every run sees the same read-size sequence.
                reader.Reset(size, FixedSeed ^ size);
                if (!Streams.TryReadExactIncremental(source, size, out _))
                    throw new InvalidOperationException("unexpected short read");
            }
        }

        private static double Median3(double a, double b, double c)
        {
            double max = System.Math.Max(a, System.Math.Max(b, c));
            double min = System.Math.Min(a, System.Math.Min(b, c));
            return a + b + c - max - min;
        }
    }
}
