using System.Collections;
using System;
using Org.BouncyCastle.Utilities;


namespace Org.BouncyCastle.Crypto.Tls
{

    class DTLSReassembler
    {
        private readonly HandshakeType msg_type;
        private readonly byte[] body;

        private IList missing = Platform.CreateArrayList();

        public DTLSReassembler(HandshakeType msg_type, int length)
        {
            this.msg_type = msg_type;
            this.body = new byte[length];
            this.missing.Add(new Range(0, length));
        }

        internal HandshakeType MessageType
        {
             get {
                return msg_type;
             }
        }

        internal byte[] GetBodyIfComplete()
        {
            return missing.Count == 0 ? body : null;
        }

        internal void ContributeFragment(HandshakeType msg_type, int length, byte[] buf, int off, int fragment_offset,
                                int fragment_length)
        {

            int fragment_end = fragment_offset + fragment_length;

            if (this.msg_type != msg_type || this.body.Length != length || fragment_end > length)
            {
                return;
            }

            if (fragment_length == 0)
            {
                // NOTE: Empty messages still require an empty fragment to complete it
                if (fragment_offset == 0 && missing.Count != 0)
                {
                    Range firstRange = (Range)missing[0];
                    if (firstRange.getEnd() == 0)
                    {
                        missing.RemoveAt(0);
                    }
                }
                return;
            }

            for (int i = 0; i < missing.Count; ++i)
            {
                Range range = (Range)missing[i];
                if (range.getStart() >= fragment_end)
                {
                    break;
                }
                if (range.getEnd() > fragment_offset)
                {

                    int copyStart = System.Math.Max(range.getStart(), fragment_offset);
                    int copyEnd = System.Math.Min(range.getEnd(), fragment_end);
                    int copyLength = copyEnd - copyStart;

                    Buffer.BlockCopy(buf, off + copyStart - fragment_offset, body, copyStart,
                        copyLength);

                    if (copyStart == range.getStart())
                    {
                        if (copyEnd == range.getEnd())
                        {
                            missing.RemoveAt(i--);
                        }
                        else
                        {
                            range.setStart(copyEnd);
                        }
                    }
                    else
                    {
                        if (copyEnd == range.getEnd())
                        {
                            range.setEnd(copyStart);
                        }
                        else
                        {
                            missing.Insert(++i, new Range(copyEnd, range.getEnd()));
                            range.setEnd(copyStart);
                        }
                    }
                }
            }
        }

        internal void Reset()
        {
            this.missing.Clear();
            this.missing.Add(new Range(0, body.Length));
        }

        private class Range
        {
            private int start, end;

            public Range(int start, int end)
            {
                this.start = start;
                this.end = end;
            }

            public int getStart()
            {
                return start;
            }

            public void setStart(int start)
            {
                this.start = start;
            }

            public int getEnd()
            {
                return end;
            }

            public void setEnd(int end)
            {
                this.end = end;
            }
        }
    }

}