using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Tls
{
    internal sealed class DtlsReassembler
    {
        /// <summary>
        /// Bounds the number of ranges tracked for one message.
        /// </summary>
        /// <remarks>
        /// Limits the amount of fragmentation a malicious peer can cause. While at the limit a fragment that would
        /// split a range is ignored; retransmission is then relied on to complete the message (although 
        /// </remarks>
        private const int MinMissingRangesLimit = 64;

        private readonly short m_msg_type;
        private readonly byte[] m_body;
        private int m_missingRangesLimit;

        private readonly List<Range> m_missing = new List<Range>();

        public DtlsReassembler(short msg_type, int length)
        {
            m_msg_type = msg_type;
            m_body = new byte[length];
            m_missingRangesLimit = System.Math.Max(MinMissingRangesLimit, length / 1024);
            m_missing.Add(new Range(0, length));
        }

        public short MsgType => m_msg_type;

        public byte[] GetBodyIfComplete() => m_missing.Count > 0 ? null : m_body;

        public void ContributeFragment(short msg_type, int length, byte[] buf, int off, int fragment_offset,
            int fragment_length)
        {
            int fragment_end = fragment_offset + fragment_length;

            if (m_msg_type != msg_type || m_body.Length != length || fragment_end > length)
                return;

            // NOTE: Empty messages still require an empty fragment to complete it
            if (fragment_length == 0)
            {
                if (fragment_offset == 0 && m_missing.Count > 0 && m_missing[0].End == 0)
                {
                    m_missing.RemoveAt(0);
                }
                return;
            }

            for (int i = FindStartIndex(fragment_offset); i < m_missing.Count; ++i)
            {
                Range range = m_missing[i];
                if (range.Start >= fragment_end)
                    break;
                if (range.End <= fragment_offset)
                    continue;

                int copyStart = System.Math.Max(range.Start, fragment_offset);
                int copyEnd = System.Math.Min(range.End, fragment_end);
                int copyLength = copyEnd - copyStart;

                if (copyStart == range.Start)
                {
                    if (copyEnd == range.End)
                    {
                        m_missing.RemoveAt(i--);
                    }
                    else
                    {
                        range.Start = copyEnd;
                    }
                }
                else
                {
                    if (copyEnd != range.End)
                    {
                        // Splitting this range would exceed the limit, so ignore the fragment
                        if (m_missing.Count >= m_missingRangesLimit)
                            continue;

                        m_missing.Insert(++i, new Range(copyEnd, range.End));
                    }
                    range.End = copyStart;
                }

                Array.Copy(buf, off + copyStart - fragment_offset, m_body, copyStart, copyLength);
            }
        }

        /// <summary>
        /// Find the index of the first range that might overlap a fragment starting at fragment_offset.
        /// </summary>
        /// <remarks>
        /// The ranges are sorted and disjoint, so every earlier one ends at or below fragment_offset and could only
        /// be skipped over.
        /// </remarks>
        private int FindStartIndex(int fragment_offset)
        {
            int lo = 0, hi = m_missing.Count;
            while (lo < hi)
            {
                int mid = (lo + hi) >> 1;
                if (m_missing[mid].End > fragment_offset)
                {
                    hi = mid;
                }
                else
                {
                    lo = mid + 1;
                }
            }
            return lo;
        }

        public void Reset()
        {
            m_missing.Clear();
            m_missing.Add(new Range(0, m_body.Length));
        }

        private sealed class Range
        {
            internal int End { get; set; }
            internal int Start { get; set; }

            internal Range(int start, int end)
            {
                Start = start;
                End = end;
            }
        }
    }
}
