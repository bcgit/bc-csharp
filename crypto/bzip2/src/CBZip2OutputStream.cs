/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * This package is based on the work done by Keiron Liddle, Aftex Software
 * <keiron@aftexsw.com> to whom the Ant project is very grateful for his
 * great code.
 */

using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Apache.Bzip2
{
	/**
    * An output stream that compresses into the BZip2 format (with the file
    * header chars) into another stream.
    *
    * @author <a href="mailto:keiron@aftexsw.com">Keiron Liddle</a>
    *
    * TODO:    Update to BZip2 1.0.1
    * <b>NB:</b> note this class has been modified to add a leading BZ to the
    * start of the BZIP2 stream to make it compatible with other PGP programs.
    */
    public class CBZip2OutputStream : Stream 
	{
        protected const int SETMASK = 1 << 21;
        protected const int CLEARMASK = ~SETMASK;
        protected const int GREATER_ICOST = 15;
        protected const int LESSER_ICOST = 0;
        protected const int SMALL_THRESH = 20;
        protected const int DEPTH_THRESH = 10;

        private bool finished;

        private static void Panic()
        {
            throw new InvalidOperationException();
        }

        private void MakeMaps()
        {
            int i;
            nInUse = 0;
            for (i = 0; i < 256; i++)
            {
                if (inUse[i])
                {
                    seqToUnseq[nInUse] = (char) i;
                    unseqToSeq[i] = (char) nInUse;
                    nInUse++;
                }
            }
        }

        protected static void HbMakeCodeLengths(byte[] len, int[] freq, int alphaSize, int maxLen)
        {
            /*
            Nodes and heap entries run from 1.  Entry 0
            for both the heap and nodes is a sentinel.
            */
            int[] heap = new int[BZip2Constants.MAX_ALPHA_SIZE + 2];
            int[] weight = new int[BZip2Constants.MAX_ALPHA_SIZE * 2];
            int[] parent = new int[BZip2Constants.MAX_ALPHA_SIZE * 2];

            for (int i = 0; i < alphaSize; i++)
            {
                weight[i + 1] = (freq[i] == 0 ? 1 : freq[i]) << 8;
            }

            while (true)
            {
                int nNodes = alphaSize;
                int nHeap = 0;

                heap[0] = 0;
                weight[0] = 0;
                parent[0] = -2;

                for (int i = 1; i <= alphaSize; i++)
                {
                    parent[i] = -1;
                    heap[++nHeap] = i;
                    {
                        int zz = nHeap;
                        int tmp = heap[zz];
                        while (weight[tmp] < weight[heap[zz >> 1]])
                        {
                            heap[zz] = heap[zz >> 1];
                            zz >>= 1;
                        }
                        heap[zz] = tmp;
                    }
                }
                if (!(nHeap < (BZip2Constants.MAX_ALPHA_SIZE + 2)))
                {
                    Panic();
                }

                while (nHeap > 1)
                {
                    int n1 = heap[1];
                    heap[1] = heap[nHeap--];
                    {
                        int zz = 1;
                        int tmp = heap[zz];
                        while (true) {
                            int yy = zz << 1;
                            if (yy > nHeap)
                                break;

                            if (yy < nHeap
                                && weight[heap[yy + 1]] < weight[heap[yy]])
                            {
                                yy++;
                            }

                            if (weight[tmp] < weight[heap[yy]])
                                break;

                            heap[zz] = heap[yy];
                            zz = yy;
                        }
                        heap[zz] = tmp;
                    }
                    int n2 = heap[1];
                    heap[1] = heap[nHeap--];
                    {
                        int zz = 1;
                        int tmp = heap[zz];
                        while (true)
                        {
                            int yy = zz << 1;
                            if (yy > nHeap)
                                break;

                            if (yy < nHeap
                                && weight[heap[yy + 1]] < weight[heap[yy]])
                            {
                                yy++;
                            }

                            if (weight[tmp] < weight[heap[yy]])
                                break;

                            heap[zz] = heap[yy];
                            zz = yy;
                        }
                        heap[zz] = tmp;
                    }
                    nNodes++;
                    parent[n1] = parent[n2] = nNodes;

                    weight[nNodes] = (int)((uint)((weight[n1] & 0xffffff00)
                                    + (weight[n2] & 0xffffff00))
                        | (uint)(1 + (((weight[n1] & 0x000000ff) >
                                (weight[n2] & 0x000000ff)) ?
                                (weight[n1] & 0x000000ff) :
                                (weight[n2] & 0x000000ff))));

                    parent[nNodes] = -1;
                    heap[++nHeap] = nNodes;
                    {
                        int zz = nHeap;
                        int tmp = heap[zz];
                        while (weight[tmp] < weight[heap[zz >> 1]])
                        {
                            heap[zz] = heap[zz >> 1];
                            zz >>= 1;
                        }
                        heap[zz] = tmp;
                    }
                }
                if (!(nNodes < (BZip2Constants.MAX_ALPHA_SIZE * 2)))
                {
                    Panic();
                }

                bool tooLong = false;
                for (int i = 1; i <= alphaSize; i++)
                {
                    int j = 0;
                    int k = i;
                    while (parent[k] >= 0)
                    {
                        k = parent[k];
                        j++;
                    }
                    len[i - 1] = (byte)j;
                    if (j > maxLen)
                    {
                        tooLong = true;
                    }
                }

                if (!tooLong)
                    break;

                for (int i = 1; i < alphaSize; i++)
                {
                    int j = weight[i] >> 8;
                    j = 1 + (j / 2);
                    weight[i] = j << 8;
                }
            }
        }

        /*
         * number of characters in the block
         */
        int count;

        /*
        index in zptr[] of original string after sorting.
        */
        int origPtr;

        /*
        always: in the range 0 .. 9.
        The current block size is 100000 * this number.
        */
        readonly int blockSize100k;

        private int allowableBlockSize;

        bool blockRandomised;

        int bsBuff;
        int bsLive;
        readonly CRC mCrc = new CRC();

        private bool[] inUse = new bool[256];
        private int nInUse;

        private char[] seqToUnseq = new char[256];
        private char[] unseqToSeq = new char[256];

        private char[] selector = new char[BZip2Constants.MAX_SELECTORS];
        private char[] selectorMtf = new char[BZip2Constants.MAX_SELECTORS];

        private byte[] blockBytes;
        private ushort[] quadrantShorts;
        private int[] zptr;
        private int[] szptr;
        private int[] ftab;

        private int nMTF;

        private int[] mtfFreq = new int[BZip2Constants.MAX_ALPHA_SIZE];

        /*
        * Used when sorting.  If too many long comparisons
        * happen, we stop sorting, randomise the block
        * slightly, and try again.
        */
        private int workFactor;
        private int workDone;
        private int workLimit;
        private bool firstAttempt;

        private int currentByte = -1;
        private int runLength = 0;

        public CBZip2OutputStream(Stream outStream)
            : this(outStream, 9)
        {
        }

        public CBZip2OutputStream(Stream outStream, int blockSize)
        {
            blockBytes = null;
            quadrantShorts = null;
            zptr = null;
            ftab = null;

            outStream.WriteByte((byte)'B');
            outStream.WriteByte((byte)'Z');

            BsSetStream(outStream);

            workFactor = 50;
            if (blockSize > 9) {
                blockSize = 9;
            }
            if (blockSize < 1) {
                blockSize = 1;
            }
            blockSize100k = blockSize;
            AllocateCompressStructures();
            Initialize();
            InitBlock();
        }

        /**
        *
        * modified by Oliver Merkel, 010128
        *
        */
        public override void WriteByte(byte b)
        {
            if (currentByte == b)
            {
                runLength++;
                if (runLength > 254)
                {
                    WriteRun();
                    currentByte = -1;
                    runLength = 0;
                }
            }
            else if (currentByte == -1)
            {
                currentByte = b;
                runLength++;
            }
            else
            {
                WriteRun();
                runLength = 1;
                currentByte = b;
            }
        }

        private void WriteRun()
        {
            if (count > allowableBlockSize)
            {
                EndBlock();
                InitBlock();
            }

            inUse[currentByte] = true;

            for (int i = 0; i < runLength; i++)
            {
                mCrc.UpdateCRC(currentByte);
            }

            switch (runLength)
            {
            case 1:
                blockBytes[++count] = (byte)currentByte;
                break;
            case 2:
                blockBytes[++count] = (byte)currentByte;
                blockBytes[++count] = (byte)currentByte;
                break;
            case 3:
                blockBytes[++count] = (byte)currentByte;
                blockBytes[++count] = (byte)currentByte;
                blockBytes[++count] = (byte)currentByte;
                break;
            default:
                inUse[runLength - 4] = true;
                blockBytes[++count] = (byte)currentByte;
                blockBytes[++count] = (byte)currentByte;
                blockBytes[++count] = (byte)currentByte;
                blockBytes[++count] = (byte)currentByte;
                blockBytes[++count] = (byte)(runLength - 4);
                break;
            }
        }

        bool closed = false;

//        protected void Finalize() {
//            Close();
//        }

#if PORTABLE
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (closed)
                    return;

                Finish();
                closed = true;
                Platform.Dispose(this.bsStream);
            }
            base.Dispose(disposing);
        }
#else
        public override void Close()
        {
            if (closed)
                return;

            Finish();

            closed = true;
            Platform.Dispose(this.bsStream);

            base.Close();
        }
#endif

        public void Finish()
        {
            if (finished)
                return;

            if (runLength > 0)
            {
                WriteRun();
            }
            currentByte = -1;
            if (count > 0)
            {
                EndBlock();
            }
            EndCompression();
            finished = true;
            Flush();
        }
        
        public override void Flush()
        {
            bsStream.Flush();
        }

        private int blockCRC, combinedCRC;

        private void Initialize()
        {
            /* Write `magic' bytes h indicating file-format == huffmanised,
            followed by a digit indicating blockSize100k.
            */
            BsPutUChar('h');
            BsPutUChar('0' + blockSize100k);

            combinedCRC = 0;
        }

        private void InitBlock()
        {
            mCrc.InitialiseCRC();
            count = 0;

            for (int i = 0; i < 256; i++)
            {
                inUse[i] = false;
            }

            /* 20 is just a paranoia constant */
            allowableBlockSize = BZip2Constants.baseBlockSize * blockSize100k - 20;
        }

        private void EndBlock()
        {
            blockCRC = mCrc.GetFinalCRC();
            combinedCRC = Integers.RotateLeft(combinedCRC, 1) ^ blockCRC;

            /* sort the block and establish posn of original string */
            DoReversibleTransformation();

            /*
            A 6-byte block header, the value chosen arbitrarily
            as 0x314159265359 :-).  A 32 bit value does not really
            give a strong enough guarantee that the value will not
            appear by chance in the compressed datastream.  Worst-case
            probability of this event, for a 900k block, is about
            2.0e-3 for 32 bits, 1.0e-5 for 40 bits and 4.0e-8 for 48 bits.
            For a compressed file of size 100Gb -- about 100000 blocks --
            only a 48-bit marker will do.  NB: normal compression/
            decompression do *not* rely on these statistical properties.
            They are only important when trying to recover blocks from
            damaged files.
            */
            BsPutUChar(0x31);
            BsPutUChar(0x41);
            BsPutUChar(0x59);
            BsPutUChar(0x26);
            BsPutUChar(0x53);
            BsPutUChar(0x59);

            /* Now the block's CRC, so it is in a known place. */
            BsPutint(blockCRC);

            /* Now a single bit indicating randomisation. */
            BsW(1, blockRandomised ? 1 : 0);

            /* Finally, block's contents proper. */
            MoveToFrontCodeAndSend();
        }

        private void EndCompression() {
            /*
            Now another magic 48-bit number, 0x177245385090, to
            indicate the end of the last block.  (Sqrt(pi), if
            you want to know.  I did want to use e, but it contains
            too much repetition -- 27 18 28 18 28 46 -- for me
            to feel statistically comfortable.  Call me paranoid.)
            */
            BsPutUChar(0x17);
            BsPutUChar(0x72);
            BsPutUChar(0x45);
            BsPutUChar(0x38);
            BsPutUChar(0x50);
            BsPutUChar(0x90);

            BsPutint(combinedCRC);

            BsFinishedWithStream();
        }

        private void HbAssignCodes(int[] code, byte[] length, int minLen, int maxLen, int alphaSize)
        {
            int vec = 0;
            for (int n = minLen; n <= maxLen; n++)
            {
                for (int i = 0; i < alphaSize; i++)
                {
                    if (length[i] == n)
                    {
                        code[i] = vec;
                        vec++;
                    }
                }
                vec <<= 1;
            }
        }

        private void BsSetStream(Stream f)
        {
            bsStream = f;
            bsLive = 0;
            bsBuff = 0;
        }

        private void BsFinishedWithStream()
        {
            while (bsLive > 0)
            {
                bsStream.WriteByte((byte)(bsBuff >> 24)); // write 8-bit
                bsBuff <<= 8;
                bsLive -= 8;
            }
        }

        private void BsW(int n, int v)
        {
            while (bsLive >= 8)
            {
                bsStream.WriteByte((byte)(bsBuff >> 24)); // write 8-bit
                bsBuff <<= 8;
                bsLive -= 8;
            }
            bsBuff |= v << (32 - bsLive - n);
            bsLive += n;
        }

        private void BsPutUChar(int c)
        {
            BsW(8, c);
        }

        private void BsPutint(int u)
        {
            //BsW(8, (u >> 24) & 0xff);
            //BsW(8, (u >> 16) & 0xff);
            //BsW(8, (u >>  8) & 0xff);
            //BsW(8,  u        & 0xff);
            BsW(16, (u >> 16) & 0xFFFF);
            BsW(16, u & 0xFFFF);
        }

        private void BsPutIntVS(int numBits, int c)
        {
            BsW(numBits, c);
        }

        private void SendMTFValues()
        {
            byte[][] len = CBZip2InputStream.InitByteArray(BZip2Constants.N_GROUPS, BZip2Constants.MAX_ALPHA_SIZE);

            int v, t, i, j, gs, ge, bt, bc, iter;
            int nSelectors = 0, alphaSize, minLen, maxLen, selCtr;
            int nGroups;

            alphaSize = nInUse + 2;
            for (t = 0; t < BZip2Constants.N_GROUPS; t++)
            {
                byte[] len_t = len[t];
                for (v = 0; v < alphaSize; v++)
                {
                    len_t[v] = GREATER_ICOST;
                }
            }

            /* Decide how many coding tables to use */
            if (nMTF <= 0)
            {
                Panic();
            }

            if (nMTF < 200)
            {
                nGroups = 2;
            }
            else if (nMTF < 600)
            {
                nGroups = 3;
            }
            else if (nMTF < 1200)
            {
                nGroups = 4;
            }
            else if (nMTF < 2400)
            {
                nGroups = 5;
            }
            else
            {
                nGroups = 6;
            }

            /* Generate an initial set of coding tables */
            {
                int tFreq, aFreq;

                int nPart = nGroups;
                int remF  = nMTF;
                gs = 0;
                while (nPart > 0)
                {
                    tFreq = remF / nPart;
                    ge = gs - 1;
                    aFreq = 0;
                    while (aFreq < tFreq && ge < alphaSize - 1)
                    {
                        aFreq += mtfFreq[++ge];
                    }

                    if (ge > gs && nPart != nGroups && nPart != 1
                        && ((nGroups - nPart) % 2 == 1))
                    {
                        aFreq -= mtfFreq[ge--];
                    }

                    byte[] len_np = len[nPart - 1];
                    for (v = 0; v < alphaSize; v++)
                    {
                        if (v >= gs && v <= ge)
                        {
                            len_np[v] = LESSER_ICOST;
                        }
                        else
                        {
                            len_np[v] = GREATER_ICOST;
                        }
                    }

                    nPart--;
                    gs = ge + 1;
                    remF -= aFreq;
                }
            }

            int[][] rfreq = CBZip2InputStream.InitIntArray(BZip2Constants.N_GROUPS, BZip2Constants.MAX_ALPHA_SIZE);
            int[] fave = new int[BZip2Constants.N_GROUPS];
            short[] cost = new short[BZip2Constants.N_GROUPS];
            byte[] len_0 = len[0];
            byte[] len_1 = len[1];
            byte[] len_2 = len[2];
            byte[] len_3 = len[3];
            byte[] len_4 = len[4];
            byte[] len_5 = len[5];

            /*
            Iterate up to N_ITERS times to improve the tables.
            */
            for (iter = 0; iter < BZip2Constants.N_ITERS; iter++)
            {
                for (t = 0; t < nGroups; t++)
                {
                    fave[t] = 0;

                    int[] rfreq_t = rfreq[t];
                    for (v = 0; v < alphaSize; v++)
                    {
                        rfreq_t[v] = 0;
                    }
                }

                nSelectors = 0;
                gs = 0;
                while (gs < nMTF)
                {
                    /* Set group start & end marks. */

                    /*
                     * Calculate the cost of this group as coded by each of the coding tables.
                     */

                    ge = System.Math.Min(gs + BZip2Constants.G_SIZE - 1, nMTF - 1);

                    if (nGroups == 6)
                    {
                        short cost0 = 0, cost1 = 0, cost2 = 0, cost3 = 0, cost4 = 0, cost5 = 0;

                        for (i = gs; i <= ge; i++)
                        {
                            int icv = szptr[i];
                            cost0 += len_0[icv];
                            cost1 += len_1[icv];
                            cost2 += len_2[icv];
                            cost3 += len_3[icv];
                            cost4 += len_4[icv];
                            cost5 += len_5[icv];
                        }

                        cost[0] = cost0;
                        cost[1] = cost1;
                        cost[2] = cost2;
                        cost[3] = cost3;
                        cost[4] = cost4;
                        cost[5] = cost5;
                    }
                    else
                    {
                        for (t = 0; t < nGroups; t++)
                        {
                            cost[t] = 0;
                        }

                        for (i = gs; i <= ge; i++)
                        {
                            int icv = szptr[i];
                            for (t = 0; t < nGroups; t++)
                            {
                                cost[t] += len[t][icv];
                            }
                        }
                    }

                    /*
                    Find the coding table which is best for this group,
                    and record its identity in the selector table.
                    */
                    bc = 999999999;
                    bt = -1;
                    for (t = 0; t < nGroups; t++)
                    {
                        if (cost[t] < bc)
                        {
                            bc = cost[t];
                            bt = t;
                        }
                    }
                    fave[bt]++;
                    selector[nSelectors] = (char) bt;
                    nSelectors++;

                    /*
                    Increment the symbol frequencies for the selected table.
                    */
                    int[] rfreq_bt = rfreq[bt];
                    for (i = gs; i <= ge; i++)
                    {
                        rfreq_bt[szptr[i]]++;
                    }

                    gs = ge + 1;
                }

                /*
                Recompute the tables based on the accumulated frequencies.
                */
                for (t = 0; t < nGroups; t++)
                {
                    HbMakeCodeLengths(len[t], rfreq[t], alphaSize, 20);
                }
            }

            rfreq = null;
            fave = null;
            cost = null;

            if (!(nGroups < 8))
            {
                Panic();
            }
            if (!(nSelectors < 32768 && nSelectors <= (2 + (900000 / BZip2Constants.G_SIZE))))
            {
                Panic();
            }

            /* Compute MTF values for the selectors. */
            {
                char[] pos = new char[BZip2Constants.N_GROUPS];
                char ll_i, tmp2, tmp;
                for (i = 0; i < nGroups; i++)
                {
                    pos[i] = (char)i;
                }
                for (i = 0; i < nSelectors; i++)
                {
                    ll_i = selector[i];
                    j = 0;
                    tmp = pos[j];
                    while (ll_i != tmp)
                    {
                        j++;
                        tmp2 = tmp;
                        tmp = pos[j];
                        pos[j] = tmp2;
                    }
                    pos[0] = tmp;
                    selectorMtf[i] = (char)j;
                }
            }

            int[][] code = CBZip2InputStream.InitIntArray(BZip2Constants.N_GROUPS, BZip2Constants.MAX_ALPHA_SIZE);

            /* Assign actual codes for the tables. */
            for (t = 0; t < nGroups; t++)
            {
                minLen = 32;
                maxLen = 0;
                byte[] len_t = len[t];
                for (i = 0; i < alphaSize; i++)
                {
                    int lti = len_t[i];
                    if (lti > maxLen)
                    {
                        maxLen = lti;
                    }
                    if (lti < minLen)
                    {
                        minLen = lti;
                    }
                }
                if (maxLen > 20)
                {
                    Panic();
                }
                if (minLen < 1)
                {
                    Panic();
                }
                HbAssignCodes(code[t], len[t], minLen, maxLen, alphaSize);
            }

            /* Transmit the mapping table. */
            {
                bool[] inUse16 = new bool[16];
                for (i = 0; i < 16; i++)
                {
                    inUse16[i] = false;
                    int i16 = i * 16;
                    for (j = 0; j < 16; j++)
                    {
                        if (inUse[i16 + j])
                        {
                            inUse16[i] = true;
                            break;
                        }
                    }
                }

				for (i = 0; i < 16; i++)
                {
                    BsW(1, inUse16[i] ? 1 : 0);
                }

                for (i = 0; i < 16; i++)
                {
                    if (inUse16[i])
                    {
                        int i16 = i * 16;
                        for (j = 0; j < 16; j++)
                        {
                            BsW(1, inUse[i16 + j] ? 1 : 0);
                        }
                    }
                }
            }

            /* Now the selectors. */
            BsW(3, nGroups);
            BsW(15, nSelectors);
            for (i = 0; i < nSelectors; i++)
            {
                int count = selectorMtf[i];
                //for (j = 0; j < count; j++)
                //{
                //    BsW(1, 1);
                //}
                //BsW(1, 0);
                while (count >= 24)
                {
                    BsW(24, 0xFFFFFF);
                    count -= 24;
                }
                BsW(count + 1, (1 << (count + 1)) - 2);
            }

            /* Now the coding tables. */
            for (t = 0; t < nGroups; t++)
            {
                byte[] len_t = len[t];
                int curr = len_t[0];
                BsW(5, curr);
                for (i = 0; i < alphaSize; i++)
                {
                    int lti = len_t[i];
                    while (curr < lti)
                    {
                        BsW(2, 2);
                        curr++; /* 10 */
                    }
                    while (curr > lti)
                    {
                        BsW(2, 3);
                        curr--; /* 11 */
                    }
                    BsW(1, 0);
                }
            }

            /* And finally, the block data proper */
            selCtr = 0;
            gs = 0;
            while (gs < nMTF)
            {
                ge = System.Math.Min(gs + BZip2Constants.G_SIZE - 1, nMTF - 1);

                int selector_selCtr = selector[selCtr];
                byte[] len_selCtr = len[selector_selCtr];
                int[] code_selCtr = code[selector_selCtr];

                for (i = gs; i <= ge; i++)
                {
                    int sfmap_i = szptr[i];
                    BsW(len_selCtr[sfmap_i], code_selCtr[sfmap_i]);
                }

                gs = ge + 1;
                selCtr++;
            }
            if (!(selCtr == nSelectors))
            {
                Panic();
            }
        }

        private void MoveToFrontCodeAndSend()
        {
            BsPutIntVS(24, origPtr);
            GenerateMTFValues();
            SendMTFValues();
        }

        private Stream bsStream;

        private void SimpleSort(int lo, int hi, int d)
        {
            int i, j, h, v;

            int bigN = hi - lo + 1;
            if (bigN < 2)
                return;

            int hp = 0;
            while (incs[hp] < bigN)
            {
                hp++;
            }
            hp--;

            for (; hp >= 0; hp--)
            {
                h = incs[hp];

                i = lo + h;
                while (i <= hi)
                {
                    /* copy 1 */
                    v = zptr[i];
                    j = i;
                    while (FullGtU(zptr[j - h] + d, v + d))
                    {
                        zptr[j] = zptr[j - h];
                        j = j - h;
                        if (j <= (lo + h - 1))
                            break;
                    }
                    zptr[j] = v;

                    /* copy 2 */
                    if (++i > hi)
                        break;

                    v = zptr[i];
                    j = i;
                    while (FullGtU(zptr[j - h] + d, v + d))
                    {
                        zptr[j] = zptr[j - h];
                        j = j - h;
                        if (j <= (lo + h - 1))
                            break;
                    }
                    zptr[j] = v;

                    /* copy 3 */
                    if (++i > hi)
                        break;

                    v = zptr[i];
                    j = i;
                    while (FullGtU(zptr[j - h] + d, v + d))
                    {
                        zptr[j] = zptr[j - h];
                        j = j - h;
                        if (j <= (lo + h - 1))
                            break;
                    }
                    zptr[j] = v;
                    i++;

                    if (workDone > workLimit && firstAttempt)
                        return;
                }
            }
        }

        private void Vswap(int p1, int p2, int n)
        {
            while (--n >= 0)
            {
                int t1 = zptr[p1], t2 = zptr[p2];
                zptr[p1++] = t2;
                zptr[p2++] = t1;
            }
        }

        private int Med3(int a, int b, int c)
        {
            return a > b
                ? (c < b ? b : c > a ? a : c)
                : (c < a ? a : c > b ? b : c);
        }

        internal class StackElem
        {
            internal int ll;
            internal int hh;
            internal int dd;
        }

        private static void PushStackElem(IList stack, int stackCount, int ll, int hh, int dd)
        {
            StackElem stackElem;
            if (stackCount < stack.Count)
            {
                stackElem = (StackElem)stack[stackCount];
            }
            else
            {
                stackElem = new StackElem();
                stack.Add(stackElem);
            }

            stackElem.ll = ll;
            stackElem.hh = hh;
            stackElem.dd = dd;
        }

        private void QSort3(int loSt, int hiSt, int dSt)
        {
            int unLo, unHi, ltLo, gtHi, n, m;

            IList stack = Platform.CreateArrayList();
            int stackCount = 0;
            StackElem stackElem;

            int lo = loSt;
            int hi = hiSt;
            int d = dSt;

            for (;;)
            {
                if (hi - lo < SMALL_THRESH || d > DEPTH_THRESH)
                {
                    SimpleSort(lo, hi, d);
                    if (stackCount < 1 || (workDone > workLimit && firstAttempt))
                        return;

                    stackElem = (StackElem)stack[--stackCount];
                    lo = stackElem.ll;
                    hi = stackElem.hh;
                    d = stackElem.dd;
                    continue;
                }

                int d1 = d + 1;
                int med = Med3(
                    blockBytes[zptr[lo] + d1],
                    blockBytes[zptr[hi] + d1],
                    blockBytes[zptr[(lo + hi) >> 1] + d1]);

                unLo = ltLo = lo;
                unHi = gtHi = hi;

                while (true)
                {
                    while (unLo <= unHi)
                    {
                        int zUnLo = zptr[unLo];
                        n = blockBytes[zUnLo + d1] - med;
                        if (n > 0)
                            break;

                        if (n == 0)
                        {
                            zptr[unLo] = zptr[ltLo];
                            zptr[ltLo++] = zUnLo;
                        }
                        unLo++;
                    }
                    while (unLo <= unHi)
                    {
                        int zUnHi = zptr[unHi];
                        n = blockBytes[zUnHi + d1] - med;
                        if (n < 0)
                            break;

                        if (n == 0)
                        {
                            zptr[unHi] = zptr[gtHi];
                            zptr[gtHi--] = zUnHi;
                        }
                        unHi--;
                    }
                    if (unLo > unHi)
                        break;

                    int temp = zptr[unLo];
                    zptr[unLo++] = zptr[unHi];
                    zptr[unHi--] = temp;
                }

                if (gtHi < ltLo)
                {
                    d = d1;
                    continue;
                }

                n = System.Math.Min(ltLo - lo, unLo - ltLo);
                Vswap(lo, unLo - n, n);

                m = System.Math.Min(hi - gtHi, gtHi - unHi);
                Vswap(unLo, hi - m + 1, m);

                n = lo + (unLo - ltLo);
                m = hi - (gtHi - unHi);

                PushStackElem(stack, stackCount++, lo, n - 1, d);
                PushStackElem(stack, stackCount++, n, m, d1);

                lo = m + 1;
            }
        }

        private void MainSort()
        {
            int i, j, ss, sb;
            int[] runningOrder = new int[256];
            int[] copy = new int[256];
            bool[] bigDone = new bool[256];
            int c1, c2;

            /*
            In the various block-sized structures, live data runs
            from 0 to last+NUM_OVERSHOOT_BYTES inclusive.  First,
            set up the overshoot area for block.
            */
            for (i = 0; i < BZip2Constants.NUM_OVERSHOOT_BYTES; i++)
            {
                blockBytes[count + i + 1] = blockBytes[(i % count) + 1];
            }
            for (i = 0; i <= count + BZip2Constants.NUM_OVERSHOOT_BYTES; i++)
            {
                quadrantShorts[i] = 0;
            }

            blockBytes[0] = blockBytes[count];

            if (count <= 4000)
            {
                /*
                Use SimpleSort(), since the full sorting mechanism
                has quite a large constant overhead.
                */
                for (i = 0; i < count; i++)
                {
                    zptr[i] = i;
                }
                firstAttempt = false;
                workDone = workLimit = 0;
                SimpleSort(0, count - 1, 0);
            }
            else
            {
                for (i = 0; i <= 255; i++)
                {
                    bigDone[i] = false;
                }

                for (i = 0; i <= 65536; i++)
                {
                    ftab[i] = 0;
                }

                c1 = blockBytes[0];
                for (i = 1; i <= count; i++)
                {
                    c2 = blockBytes[i];
                    ftab[(c1 << 8) + c2]++;
                    c1 = c2;
                }

                for (i = 0; i < 65536; i++)
                {
                    ftab[i + 1] += ftab[i];
                }

                c1 = blockBytes[1];
                for (i = 0; i < (count - 1); i++)
                {
                    c2 = blockBytes[i + 2];
                    j = (c1 << 8) + c2;
                    c1 = c2;
                    ftab[j]--;
                    zptr[ftab[j]] = i;
                }

                j = ((int)blockBytes[count] << 8) + blockBytes[1];
                ftab[j]--;
                zptr[ftab[j]] = count - 1;

                /*
                Now ftab contains the first loc of every small bucket.
                Calculate the running order, from smallest to largest
                big bucket.
                */

                for (i = 0; i <= 255; i++)
                {
                    runningOrder[i] = i;
                }

                {
                    int h = 1;
                    do
                    {
                        h = 3 * h + 1;
                    }
                    while (h <= 256);
                    do
                    {
                        h = h / 3;
                        for (i = h; i <= 255; i++)
                        {
                            int vv = runningOrder[i];
                            j = i;
                            while ((ftab[(runningOrder[j - h] + 1) << 8] - ftab[runningOrder[j - h] << 8])
                                > (ftab[(vv + 1) << 8] - ftab[vv << 8]))
                            {
                                runningOrder[j] = runningOrder[j - h];
                                j = j - h;
                                if (j < h)
                                    break;
                            }
                            runningOrder[j] = vv;
                        }
                    }
                    while (h != 1);
                }

                /*
                The main sorting loop.
                */
                for (i = 0; i <= 255; i++)
                {
                    /*
                    Process big buckets, starting with the least full.
                    */
                    ss = runningOrder[i];

                    /*
                    Complete the big bucket [ss] by quicksorting
                    any unsorted small buckets [ss, j].  Hopefully
                    previous pointer-scanning phases have already
                    completed many of the small buckets [ss, j], so
                    we don't have to sort them at all.
                    */
                    for (j = 0; j <= 255; j++)
                    {
                        sb = (ss << 8) + j;
                        if ((ftab[sb] & SETMASK) != SETMASK)
                        {
                            int lo = ftab[sb] & CLEARMASK;
                            int hi = (ftab[sb + 1] & CLEARMASK) - 1;
                            if (hi > lo)
                            {
                                QSort3(lo, hi, 2);
                                if (workDone > workLimit && firstAttempt)
                                    return;
                            }
                            ftab[sb] |= SETMASK;
                        }
                    }

                    /*
                    The ss big bucket is now done.  Record this fact,
                    and update the quadrant descriptors.  Remember to
                    update quadrants in the overshoot area too, if
                    necessary.  The "if (i < 255)" test merely skips
                    this updating for the last bucket processed, since
                    updating for the last bucket is pointless.
                    */
                    bigDone[ss] = true;

                    if (i < 255)
                    {
                        int bbStart = ftab[ss << 8] & CLEARMASK;
                        int bbSize = (ftab[(ss + 1) << 8] & CLEARMASK) - bbStart;

                        int shifts = 0;
                        while ((bbSize >> shifts) > 65534)
                        {
                            shifts++;
                        }

                        for (j = 0; j < bbSize; j++)
                        {
                            int a2update = zptr[bbStart + j] + 1;
                            ushort qVal = (ushort)(j >> shifts);
                            quadrantShorts[a2update] = qVal;
                            if (a2update <= BZip2Constants.NUM_OVERSHOOT_BYTES)
                            {
                                quadrantShorts[a2update + count] = qVal;
                            }
                        }

                        if (!(((bbSize - 1) >> shifts) <= 65535))
                        {
                            Panic();
                        }
                    }

                    /*
                    Now scan this big bucket so as to synthesise the
                    sorted order for small buckets [t, ss] for all t != ss.
                    */
                    for (j = 0; j <= 255; j++)
                    {
                        copy[j] = ftab[(j << 8) + ss] & CLEARMASK;
                    }

                    for (j = ftab[ss << 8] & CLEARMASK;
                        j < (ftab[(ss + 1) << 8] & CLEARMASK); j++)
                    {
                        int zptr_j = zptr[j];
                        c1 = blockBytes[zptr_j];
                        if (!bigDone[c1])
                        {
                            zptr[copy[c1]] = (zptr_j == 0 ? count : zptr_j) - 1;
                            copy[c1]++;
                        }
                    }

                    for (j = 0; j <= 255; j++)
                    {
                        ftab[(j << 8) + ss] |= SETMASK;
                    }
                }
            }
        }

        private void RandomiseBlock()
        {
            for (int i = 0; i < 256; i++)
            {
                inUse[i] = false;
            }

            int rNToGo = 0;
            int rTPos = 0;

            for (int i = 0; i < count; i++)
            {
                if (rNToGo == 0)
                {
                    rNToGo = BZip2Constants.rNums[rTPos];

                    if (++rTPos == 512)
                    {
                        rTPos = 0;
                    }
                }
                rNToGo--;
                blockBytes[i + 1] ^= (byte)((rNToGo == 1) ? 1 : 0);

                inUse[blockBytes[i + 1]] = true;
            }
        }

        private void DoReversibleTransformation()
        {
            workLimit = workFactor * (count - 1);
            workDone = 0;
            blockRandomised = false;
            firstAttempt = true;

            MainSort();

            if (workDone > workLimit && firstAttempt)
            {
                RandomiseBlock();
                workLimit = workDone = 0;
                blockRandomised = true;
                firstAttempt = false;
                MainSort();
            }

            origPtr = -1;
            for (int i = 0; i < count; i++)
            {
                if (zptr[i] == 0)
                {
                    origPtr = i;
                    break;
                }
            }

            if (origPtr == -1)
            {
                Panic();
            }
        }

        private bool FullGtU(int i1, int i2)
        {
            int c1, c2;

            c1 = blockBytes[++i1];
            c2 = blockBytes[++i2];
            if (c1 != c2)
                return c1 > c2;

            c1 = blockBytes[++i1];
            c2 = blockBytes[++i2];
            if (c1 != c2)
                return c1 > c2;

            c1 = blockBytes[++i1];
            c2 = blockBytes[++i2];
            if (c1 != c2)
                return c1 > c2;

            c1 = blockBytes[++i1];
            c2 = blockBytes[++i2];
            if (c1 != c2)
                return c1 > c2;

            c1 = blockBytes[++i1];
            c2 = blockBytes[++i2];
            if (c1 != c2)
                return c1 > c2;

            c1 = blockBytes[++i1];
            c2 = blockBytes[++i2];
            if (c1 != c2)
                return c1 > c2;

            int k = count;
            int s1, s2;

            do
            {
                c1 = blockBytes[++i1];
                c2 = blockBytes[++i2];
                if (c1 != c2)
                    return c1 > c2;

                s1 = quadrantShorts[i1];
                s2 = quadrantShorts[i2];
                if (s1 != s2)
                    return s1 > s2;

                c1 = blockBytes[++i1];
                c2 = blockBytes[++i2];
                if (c1 != c2)
                    return c1 > c2;

                s1 = quadrantShorts[i1];
                s2 = quadrantShorts[i2];
                if (s1 != s2)
                    return s1 > s2;

                c1 = blockBytes[++i1];
                c2 = blockBytes[++i2];
                if (c1 != c2)
                    return c1 > c2;

                s1 = quadrantShorts[i1];
                s2 = quadrantShorts[i2];
                if (s1 != s2)
                    return s1 > s2;

                c1 = blockBytes[++i1];
                c2 = blockBytes[++i2];
                if (c1 != c2)
                    return c1 > c2;

                s1 = quadrantShorts[i1];
                s2 = quadrantShorts[i2];
                if (s1 != s2)
                    return s1 > s2;

                if (i1 >= count)
                {
                    i1 -= count;
                }
                if (i2 >= count)
                {
                    i2 -= count;
                }

                k -= 4;
                workDone++;
            }
            while (k >= 0);

            return false;
        }

        /*
        Knuth's increments seem to work better
        than Incerpi-Sedgewick here.  Possibly
        because the number of elems to sort is
        usually small, typically <= 20.
        */
        private static readonly int[] incs = { 1, 4, 13, 40, 121, 364, 1093, 3280, 9841, 29524, 88573, 265720, 797161,
            2391484 };

        private void AllocateCompressStructures()
        {
            int n = BZip2Constants.baseBlockSize * blockSize100k;
            blockBytes = new byte[(n + 1 + BZip2Constants.NUM_OVERSHOOT_BYTES)];
            quadrantShorts = new ushort[(n + 1 + BZip2Constants.NUM_OVERSHOOT_BYTES)];
            zptr = new int[n];
            ftab = new int[65537];

            /*
            The back end needs a place to store the MTF values
            whilst it calculates the coding tables.  We could
            put them in the zptr array.  However, these values
            will fit in a short, so we overlay szptr at the
            start of zptr, in the hope of reducing the number
            of cache misses induced by the multiple traversals
            of the MTF values when calculating coding tables.
            Seems to improve compression speed by about 1%.
            */
            // NOTE: We can't "overlay" in C#, so we just share zptr
            szptr = zptr;
        }

        private void GenerateMTFValues()
        {
            char[] yy = new char[256];
            int  i, j;
            char tmp;
            char tmp2;
            int zPend;
            int wr;
            int EOB;

            MakeMaps();
            EOB = nInUse + 1;

            for (i = 0; i <= EOB; i++)
            {
                mtfFreq[i] = 0;
            }

            wr = 0;
            zPend = 0;
            for (i = 0; i < nInUse; i++)
            {
                yy[i] = (char) i;
            }

            for (i = 0; i < count; i++)
            {
                char ll_i;

                ll_i = unseqToSeq[blockBytes[zptr[i]]];

                j = 0;
                tmp = yy[j];
                while (ll_i != tmp)
                {
                    j++;
                    tmp2 = tmp;
                    tmp = yy[j];
                    yy[j] = tmp2;
                }
                yy[0] = tmp;

                if (j == 0)
                {
                    zPend++;
                }
                else
                {
                    if (zPend > 0)
                    {
                        zPend--;
                        while (true)
                        {
                            switch (zPend % 2)
                            {
                            case 0:
                                szptr[wr++] = BZip2Constants.RUNA;
                                mtfFreq[BZip2Constants.RUNA]++;
                                break;
                            case 1:
                                szptr[wr++] = BZip2Constants.RUNB;
                                mtfFreq[BZip2Constants.RUNB]++;
                                break;
                            }

                            if (zPend < 2)
                                break;

                            zPend = (zPend - 2) / 2;
                        }
                        zPend = 0;
                    }
                    szptr[wr++] = j + 1;
                    mtfFreq[j + 1]++;
                }
            }

            if (zPend > 0)
            {
                zPend--;
                while (true)
                {
                    switch (zPend % 2)
                    {
                    case 0:
                        szptr[wr++] = BZip2Constants.RUNA;
                        mtfFreq[BZip2Constants.RUNA]++;
                        break;
                    case 1:
                        szptr[wr++] = BZip2Constants.RUNB;
                        mtfFreq[BZip2Constants.RUNB]++;
                        break;
                    }

                    if (zPend < 2)
                        break;

                    zPend = (zPend - 2) / 2;
                }
            }

            szptr[wr++] = EOB;
            mtfFreq[EOB]++;

            nMTF = wr;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return 0;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return 0;
        }

        public override void SetLength(long value)
        {
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            for (int k = 0; k < count; ++k)
            {
                WriteByte(buffer[k + offset]);
            }
        }

        public override bool CanRead
        {
            get { return false; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        public override long Length
        {
            get { return 0; }
        }

        public override long Position
        {
            get { return 0; }
            set {}
        }
    }
}
