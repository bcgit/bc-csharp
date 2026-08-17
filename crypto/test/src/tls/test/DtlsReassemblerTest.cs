// DtlsReassembler's is assembly-internal. Remove guards for checks or if InternalsVisibleTo is ever added.
#if false
using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>
    /// <see cref="DtlsReassembler"/> tracks the not-yet-received ranges of a handshake message in a list that is
    /// updated as fragments arrive. These tests include basic correctness checks, but also malicious patterns
    /// of fragmentation.
    /// </summary>
    [TestFixture]
    public class DtlsReassemblerTest
    {
        private const short MsgType = HandshakeType.certificate;

        [Test]
        public void AlternatingSingleByteFragmentsStayCheap()
        {
            int length = 128 * 1024;

            DtlsReassembler r = new DtlsReassembler(MsgType, length);

            long start = DateTimeUtilities.CurrentUnixMs();

            // the hostile shape: one byte at every second offset, each splitting a tracked range
            for (int off = 0; off + 1 < length; off += 2)
            {
                r.ContributeFragment(MsgType, length, new byte[]{ 0xFF }, 0, off, 1);
            }

            long elapsed = DateTimeUtilities.CurrentUnixMs() - start;

            // uncapped this is ~70s at this length; capped it is milliseconds
            Assert.Less(elapsed, 10000L, "reassembly took " + elapsed + "ms");

            // half the bytes are still missing, so the message must not be complete
            Assert.Null(r.GetBodyIfComplete());
        }

        [Test]
        public void CapDoesNotPreventCompletion()
        {
            int length = 8192;

            byte[] full = new byte[length];
            for (int i = 0; i != length; ++i)
            {
                full[i] = (byte)i;
            }

            DtlsReassembler r = new DtlsReassembler(MsgType, length);

            for (int off = 0; off + 1 < length; off += 2)
            {
                r.ContributeFragment(MsgType, length, new byte[]{ full[off] }, 0, off, 1);
            }
            Assert.Null(r.GetBodyIfComplete());

            // retransmitting the whole flight still completes the message, gaps and cap notwithstanding
            r.ContributeFragment(MsgType, length, full, 0, 0, length);

            Assert.That(Arrays.AreEqual(full, r.GetBodyIfComplete()));
        }

        [Test]
        public void EmptyMessageAndReset()
        {
            DtlsReassembler empty = new DtlsReassembler(MsgType, 0);
            Assert.Null(empty.GetBodyIfComplete());
            empty.ContributeFragment(MsgType, 0, new byte[0], 0, 0, 0);
            Assert.NotNull(empty.GetBodyIfComplete());

            byte[] data = new byte[]{ 1, 2, 3, 4 };
            DtlsReassembler r = new DtlsReassembler(MsgType, 4);
            r.ContributeFragment(MsgType, 4, data, 0, 0, 4);
            Assert.NotNull(r.GetBodyIfComplete());

            r.Reset();
            Assert.Null(r.GetBodyIfComplete());
        }

        [Test]
        public void FirstFragmentToCoverAByteWins()
        {
            int length = 4;

            DtlsReassembler r = new DtlsReassembler(MsgType, length);

            r.ContributeFragment(MsgType, length, new byte[]{ 1, 2 }, 0, 0, 2);

            // a later fragment must not rewrite bytes already held
            r.ContributeFragment(MsgType, length, new byte[]{ 9, 9, 3, 4 }, 0, 0, 4);

            Assert.That(Arrays.AreEqual(new byte[]{ 1, 2, 3, 4 }, r.GetBodyIfComplete()));
        }

        [Test]
        public void InOrderAndReverseOrderReassembly()
        {
            int length = 4096;
            int fragmentLength = 512;

            byte[] expected = new byte[length];
            for (int i = 0; i != length; ++i)
            {
                expected[i] = (byte)(i * 7);
            }

            DtlsReassembler forwards = new DtlsReassembler(MsgType, length);
            for (int off = 0; off != length; off += fragmentLength)
            {
                Assert.Null(forwards.GetBodyIfComplete());
                forwards.ContributeFragment(MsgType, length, expected, off, off, fragmentLength);
            }
            Assert.That(Arrays.AreEqual(expected, forwards.GetBodyIfComplete()));

            DtlsReassembler backwards = new DtlsReassembler(MsgType, length);
            for (int off = length - fragmentLength; off >= 0; off -= fragmentLength)
            {
                Assert.Null(backwards.GetBodyIfComplete());
                backwards.ContributeFragment(MsgType, length, expected, off, off, fragmentLength);
            }
            Assert.That(Arrays.AreEqual(expected, backwards.GetBodyIfComplete()));
        }

        [Test]
        public void OverlappingAndDuplicateFragments()
        {
            int length = 100;

            byte[] expected = new byte[length];
            for (int i = 0; i != length; ++i)
            {
                expected[i] = (byte)(0x40 + i);
            }

            DtlsReassembler r = new DtlsReassembler(MsgType, length);

            r.ContributeFragment(MsgType, length, expected, 20, 20, 30);
            r.ContributeFragment(MsgType, length, expected, 20, 20, 30);
            r.ContributeFragment(MsgType, length, expected, 40, 40, 40);
            Assert.Null(r.GetBodyIfComplete());

            r.ContributeFragment(MsgType, length, expected, 0, 0, 25);
            Assert.Null(r.GetBodyIfComplete());

            r.ContributeFragment(MsgType, length, expected, 75, 75, 25);
            Assert.That(Arrays.AreEqual(expected, r.GetBodyIfComplete()));
        }
    }
}
#endif
