using NUnit.Framework;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// The RFC 8391 sec. 2.5 hash-address word layout. The address is the domain separation between every hash
    /// call XMSS makes, so its byte layout is as much a part of the wire format as the signature encoding is.
    /// </summary>
    [TestFixture]
    public class AddressTests
    {
        private const int Layer = 0;
        private const int Tree = 4;
        private const int Type = 12;
        private const int Word4 = 16;
        private const int Word5 = 20;
        private const int Word6 = 24;
        private const int KeyAndMask = 28;

        /// <summary>
        /// An OTS hash address with every word of it set to something distinguishable. The chain address, the
        /// hash address and the key-and-mask are not factory parameters, so they are written here through the
        /// offset constants the way the walks write them.
        /// </summary>
        private static byte[] OtsHashAddress()
        {
            byte[] enc = XmssAddress.OtsHashAddress(7, 0x0102030405060708L, 0x11223344);

            Pack.UInt32_To_BE(0x55667788U, enc, XmssAddress.ChainAddressOffset);
            Pack.UInt32_To_BE(0x99aabbccU, enc, XmssAddress.HashAddressOffset);
            Pack.UInt32_To_BE(2U, enc, XmssAddress.KeyAndMaskOffset);

            return enc;
        }

        [Test]
        public void TestOtsHashAddressLayout()
        {
            // the three words the factory does not take are zero in what it produces
            byte[] fresh = XmssAddress.OtsHashAddress(7, 0x0102030405060708L, 0x11223344);

            Assert.AreEqual(0U, Pack.BE_To_UInt32(fresh, Word5));
            Assert.AreEqual(0U, Pack.BE_To_UInt32(fresh, Word6));
            Assert.AreEqual(0U, Pack.BE_To_UInt32(fresh, KeyAndMask));

            byte[] enc = OtsHashAddress();

            Assert.AreEqual(32, enc.Length);
            Assert.AreEqual(7U, Pack.BE_To_UInt32(enc, Layer));
            Assert.AreEqual(0x0102030405060708UL, Pack.BE_To_UInt64(enc, Tree));
            Assert.AreEqual(0x00U, Pack.BE_To_UInt32(enc, Type));
            Assert.AreEqual(0x11223344U, Pack.BE_To_UInt32(enc, Word4));
            Assert.AreEqual(0x55667788U, Pack.BE_To_UInt32(enc, Word5));
            Assert.AreEqual(0x99aabbccU, Pack.BE_To_UInt32(enc, Word6));
            Assert.AreEqual(2U, Pack.BE_To_UInt32(enc, KeyAndMask));
        }

        /// <summary>
        /// An L-tree address is produced from the OTS hash address of the leaf it belongs to, and the twelve
        /// bytes naming the tree are the whole of what comes across (RFC 8391 sec. 2.5 copy_subtree_addr).
        /// </summary>
        [Test]
        public void TestLTreeAddressLayout()
        {
            byte[] enc = XmssAddress.SubtreeAddressOf(OtsHashAddress(), XmssAddress.LTreeType);

            Assert.AreEqual(32, enc.Length);
            Assert.AreEqual(7U, Pack.BE_To_UInt32(enc, Layer));
            Assert.AreEqual(0x0102030405060708UL, Pack.BE_To_UInt64(enc, Tree));
            Assert.AreEqual(0x01U, Pack.BE_To_UInt32(enc, Type));
            Assert.AreEqual(0U, Pack.BE_To_UInt32(enc, Word4));
            Assert.AreEqual(0U, Pack.BE_To_UInt32(enc, Word5));
            Assert.AreEqual(0U, Pack.BE_To_UInt32(enc, Word6));
            Assert.AreEqual(0U, Pack.BE_To_UInt32(enc, KeyAndMask));

            Pack.UInt32_To_BE(0x11223344U, enc, XmssAddress.LTreeAddressOffset);
            Pack.UInt32_To_BE(0x55667788U, enc, XmssAddress.TreeHeightOffset);
            Pack.UInt32_To_BE(0x99aabbccU, enc, XmssAddress.TreeIndexOffset);

            Assert.AreEqual(0x11223344U, Pack.BE_To_UInt32(enc, Word4));
            Assert.AreEqual(0x55667788U, Pack.BE_To_UInt32(enc, Word5));
            Assert.AreEqual(0x99aabbccU, Pack.BE_To_UInt32(enc, Word6));
        }

        /// <summary>
        /// The same for the hash tree address, whose word 4 is a reserved padding word rather than an index - so
        /// it is left where the copy leaves it, and nothing writes it.
        /// </summary>
        [Test]
        public void TestHashTreeAddressLayout()
        {
            byte[] enc = XmssAddress.SubtreeAddressOf(OtsHashAddress(), XmssAddress.HashTreeType);

            Assert.AreEqual(32, enc.Length);
            Assert.AreEqual(7U, Pack.BE_To_UInt32(enc, Layer));
            Assert.AreEqual(0x0102030405060708UL, Pack.BE_To_UInt64(enc, Tree));
            Assert.AreEqual(0x02U, Pack.BE_To_UInt32(enc, Type));
            Assert.AreEqual(0U, Pack.BE_To_UInt32(enc, Word4));
            Assert.AreEqual(0U, Pack.BE_To_UInt32(enc, Word5));
            Assert.AreEqual(0U, Pack.BE_To_UInt32(enc, Word6));
            Assert.AreEqual(0U, Pack.BE_To_UInt32(enc, KeyAndMask));

            Pack.UInt32_To_BE(0x55667788U, enc, XmssAddress.TreeHeightOffset);
            Pack.UInt32_To_BE(0x99aabbccU, enc, XmssAddress.TreeIndexOffset);

            Assert.AreEqual(0U, Pack.BE_To_UInt32(enc, Word4));
            Assert.AreEqual(0x55667788U, Pack.BE_To_UInt32(enc, Word5));
            Assert.AreEqual(0x99aabbccU, Pack.BE_To_UInt32(enc, Word6));
        }
    }
}
