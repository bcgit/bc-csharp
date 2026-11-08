using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// The versioned binary form <see cref="BdsStateCodec"/> writes the BDS traversal state of a private key in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The three methods of the Java fixture of this name are all about XMSS^MT state maps, and two of them about
    /// state Java object serialization wrote, which is not ported (see <see cref="XmssUtilities.Deserialize"/>).
    /// The XMSS^MT one arrives with the state map; what is here is the XMSS half of the codec, checked against
    /// encodings bc-java e40316b produced for the same seeds.
    /// </para>
    /// <para>
    /// The Java vectors were made with <c>new BDS(params, publicSeed, secretSeed, new byte[32], index)</c>, the
    /// public seed being the bytes 0, 1, ..., n - 1 and the secret seed 0x80, 0x81, ..., and encoded with
    /// <c>BDSStateCodec.encode(state, publicSeed)</c>; the "next" vectors are <c>getNextState</c> of that state.
    /// </para>
    /// </remarks>
    [TestFixture]
    public class BdsStateSerializationTests
    {
        private const string Sha256H4I5Root = "f2874d44455b127025c0aa718567ee143c959b2ad5a00961112c640413a7fe65";
        private const string Sha256H4I5Encoding =
            "424453000000000100000004000000020000000f0000000500010000000400000020f2874d44455b127025c0aa718567" +
            "ee143c959b2ad5a00961112c640413a7fe65000000040000000000000020610bcaf9592b89a2d55fb947f9f06c0a24b3" +
            "286c4bfc73dba08276313dfa593f0000000100000020398c477863caa47c4b045b42c096bec7c8229f6871f81d0ced40" +
            "2f63e1c0c4550000000200000020d3ba649151e0a6a6ea852228decf5ae80cd3e44683d29b90b6092ce67b7bbdc50000" +
            "0003000000206fc6ec661320956fc98f15eb9e118b009a872d3ef47d7c4a9273b4c5fc215afe00000001000000020000" +
            "000100000002000000209152955b778ea0166075fb1a463fea4ca905ed2a5597daf55c1c55c5c2f6d2e1000000000000" +
            "00020000000000000000000000070101010000000000000020819d31ed4fa017a6f9eefd3a4ec0613ffc3b8df85e79fa" +
            "bb7861c8698e63c25e00000001000000000000000b0100010000000000000020372e0d88a1f0dd3272b421cd6c692e56" +
            "112f3e61d3b75eee9cc9e7c5d548d6ec0000000200000000000000000000002011175c3fe4a9f319f00326e508a235d1" +
            "a0e066914022ff9a374adeed813252500000000200000002000000206c877b82c30728f125761f212d1d0bcad0a34b29" +
            "1387a0fbcf65dfa8afb364793f848125987212758e4126833bb7bc58cc274461209c4eae9c0fd41b61115e56";
        private const string Sha256H4I5NextEncoding =
            "424453000000000100000004000000020000000f0000000600010000000400000020f2874d44455b127025c0aa718567" +
            "ee143c959b2ad5a00961112c640413a7fe65000000040000000000000020819d31ed4fa017a6f9eefd3a4ec0613ffc3b" +
            "8df85e79fabb7861c8698e63c25e00000001000000200515e40d7379f2afad0e8a45921faeb0d0f9d361c2753f43015f" +
            "9b413ca4c1da0000000200000020d3ba649151e0a6a6ea852228decf5ae80cd3e44683d29b90b6092ce67b7bbdc50000" +
            "0003000000206fc6ec661320956fc98f15eb9e118b009a872d3ef47d7c4a9273b4c5fc215afe00000001000000020000" +
            "000100000002000000209152955b778ea0166075fb1a463fea4ca905ed2a5597daf55c1c55c5c2f6d2e1000000000000" +
            "00020000000000000000000000090101010000000000000020ece98b704a906e2fc55f718a240ed402983204361db0e9" +
            "dc7b543ea294852e6b00000001000000000000000b0100010000000000000020372e0d88a1f0dd3272b421cd6c692e56" +
            "112f3e61d3b75eee9cc9e7c5d548d6ec000000010000000200000002000000206c877b82c30728f125761f212d1d0bca" +
            "d0a34b291387a0fbcf65dfa8afb36479e451f682cba134c50ce7ef2d41d1c930d7e86f8617ad7cd13e28efaf747203ee";

        private const string Shake256192H6I11Root = "ebfc3ed9ad05f2d41287dfcd5e7b161ebeae58d55a58da6f";
        private const string Shake256192H6I11Encoding =
            "424453000000000100000006000000020000003f0000000b00010000000600000018ebfc3ed9ad05f2d41287dfcd5e7b" +
            "161ebeae58d55a58da6f0000000600000000000000180adb5ea1ec22e1dfc8240b89bc609457598dd3b54aa845e20000" +
            "000100000018a191f9498538c3b589c33a0a861e330c8c653462703b42ac0000000200000018541e52b4642ff257e183" +
            "1bc90307a0f8faea2979f24e049500000003000000184f314878e202d0e99ce753b6c532efb92d15d6b8f768802a0000" +
            "000400000018fec2fde4ffb7cdfb36de833066d52c31dc281fa7d8cb21970000000500000018634c838d79cc8f58b18b" +
            "7120b508edf0c1688099098b1e0300000001000000040000000100000004000000187a61fe17efef73b45a0fb56f1188" +
            "82b33b9dbd498ca4256a000000000000000400000000000000000000000d0101010000000000000018917a9c8d181f50" +
            "d746024074f34317bec7eab2b3f4812e6700000001000000000000000f0101010000000100000018169f83989bef87a1" +
            "b20116f2b892e5e6f80c213250da7b410000000200000000000000170101010000000200000018453c08d4bb59caf06c" +
            "7610cf8b72eb17dcf7812132a8991e00000003000000030000000000010100000003000000184e63bb75df954971b2e0" +
            "fe9ded712fd5daed14dcad9087dc000000020000000100000001000000186bd6adb18bd7032a894664d77bd397c7a7a0" +
            "528b537152fa00000003000000030000001855f5ef98318cc93c3ad518ad10a3dfdee4c8a1bb29f512814be2f947be16" +
            "d8a007a4ae62b2a188d93398d75094c532c1a25c48e6b7b85f18";
        private const string Shake256192H6I11NextEncoding =
            "424453000000000100000006000000020000003f0000000c00010000000600000018ebfc3ed9ad05f2d41287dfcd5e7b" +
            "161ebeae58d55a58da6f000000060000000000000018917a9c8d181f50d746024074f34317bec7eab2b3f4812e670000" +
            "000100000018169f83989bef87a1b20116f2b892e5e6f80c213250da7b410000000200000018dd6fcf55725b9f83f6ea" +
            "4bbe6ec9ff47f1afc93545be940600000003000000184f314878e202d0e99ce753b6c532efb92d15d6b8f768802a0000" +
            "000400000018fec2fde4ffb7cdfb36de833066d52c31dc281fa7d8cb21970000000500000018634c838d79cc8f58b18b" +
            "7120b508edf0c1688099098b1e0300000001000000040000000100000004000000187a61fe17efef73b45a0fb56f1188" +
            "82b33b9dbd498ca4256a000000000000000400000000000000000000000f0101010000000000000018d16d6d2c089f4e" +
            "a97750b00ac294b92e993b13b08c661a9c000000010000000000000013010001000000000000001835007db4a2698df5" +
            "0501faca83a33ec0adcc0a8f34e4694e0000000200000000000000170101010000000200000018453c08d4bb59caf06c" +
            "7610cf8b72eb17dcf7812132a8991e00000003000000030000000000010100000003000000184e63bb75df954971b2e0" +
            "fe9ded712fd5daed14dcad9087dc0000000100000003000000030000001855f5ef98318cc93c3ad518ad10a3dfdee4c8" +
            "a1bb29f51281ee307ef3470d0b85d49521e489c7896909342cb1af6c4457b16b7ddbb1560c73";

        private const string Sha256H8I125Root = "a7e3097b99c15486257883f848d20f4d7068b1fe79b3be5d388ad407bad5c1f1";
        private const string Sha256H8I125Encoding =
            "42445300000000010000000800000002000000ff0000007d00010000000800000020a7e3097b99c15486257883f848d2" +
            "0f4d7068b1fe79b3be5d388ad407bad5c1f10000000800000000000000201716efe2c451270fb2cf5e93ca65fa57e2cb" +
            "582ef35a29c845cf27239b341067000000010000002024a874f393388aa552abfb4178876b0599362bc5e4cf6f18b7a8" +
            "6eab1c6861a5000000020000002086453ed90a014292ce1e71c93918cee24044fd26e946b59a494b93f1bcb1156f0000" +
            "0003000000206429553d0f1a95fc4e9195e5ff5fbc7193acfa53d178117b75a849cebb2b892a0000000400000020b3f3" +
            "60136593c14005dbd032345f774e1e526340e1e933185fc3908ea78579c90000000500000020555f704740af0b0591dd" +
            "7eaa286151d305a2d6962a9bd9b8f92bab00279c194900000006000000207c0ffd83b868c71d0f8ffe37ebd178cfe563" +
            "47810723fe29e89a1558b58f2fa60000000700000020b5d2f2d930185f0b448c9af53b6b3a6a2776462ac9a894017a96" +
            "726e36e650350000000100000006000000010000000600000020e0907c967942a21c92c1d504fafcd3e95b6df3f64b20" +
            "11fffe2f0e651069ebca0000000300000003000000202ab08651086516ea8873e8f05cf2aed74fa7442eaacae8ec8fcc" +
            "281d7257d5920000000100000020be100d46d6031c51122b5ee6082fa107cfd249a62cb0aee6f1caa3afbbdc9cce0000" +
            "000000000020a021cbee1eb09acdad90e83d266ac9c2ce6fd56e98052ad6ba0a630655c8144300000006000000000000" +
            "00000000007f010101000000000000002044d27e1bea7db6dea18e58f171fc6d5467b4cd33ef0b3f8f3f6435dbf897f4" +
            "da000000010000000000000083010101000000010000002014cae4d344f5f84aaff20c6d401004d217688be3bc5fed3f" +
            "36738abf6f922b0900000002000000000000008701010100000002000000209c4396f9468333b686a42a14eb9341c490" +
            "9b61448f98dbe5b91d16b345490ae100000003000000000000008f0101010000000300000020f3fa114a95021c684db2" +
            "a3a04a74369b99ce774b94f67c53afa9e7081d42543000000004000000000000009f010101000000040000002026c6f4" +
            "10dd29398ee55090c47e4378961117420bcbd7d98b50e1daf94a3b69050000000500000000000000bb01000100000004" +
            "000000206961b6bb2720dcddc5b8a371ed9aa5f8d7ca0c969d011269b545050443739787000000020000000000000000" +
            "0000002007e832cb8d084b40827a0638a6181a7a987d02a52ad341b24dfaf49bd65b9599000000060000000600000020" +
            "f0b182c18e53e9744547cea840b40ec8a583b688bab7d3d8caade9de37edb18439dd9a5d84c164027d20f0c03414267c" +
            "d8de38c4db16caedb3da354c17fe9690";
        private const string Sha256H8I125NextEncoding =
            "42445300000000010000000800000002000000ff0000007e00010000000800000020a7e3097b99c15486257883f848d2" +
            "0f4d7068b1fe79b3be5d388ad407bad5c1f100000008000000000000002044d27e1bea7db6dea18e58f171fc6d5467b4" +
            "cd33ef0b3f8f3f6435dbf897f4da0000000100000020e1c5cefbecd2def388e64ec174376fbe3ce0388ad39ea44564b2" +
            "94356dfd72a9000000020000002086453ed90a014292ce1e71c93918cee24044fd26e946b59a494b93f1bcb1156f0000" +
            "0003000000206429553d0f1a95fc4e9195e5ff5fbc7193acfa53d178117b75a849cebb2b892a0000000400000020b3f3" +
            "60136593c14005dbd032345f774e1e526340e1e933185fc3908ea78579c90000000500000020555f704740af0b0591dd" +
            "7eaa286151d305a2d6962a9bd9b8f92bab00279c194900000006000000207c0ffd83b868c71d0f8ffe37ebd178cfe563" +
            "47810723fe29e89a1558b58f2fa60000000700000020b5d2f2d930185f0b448c9af53b6b3a6a2776462ac9a894017a96" +
            "726e36e650350000000100000006000000010000000600000020e0907c967942a21c92c1d504fafcd3e95b6df3f64b20" +
            "11fffe2f0e651069ebca0000000300000003000000202ab08651086516ea8873e8f05cf2aed74fa7442eaacae8ec8fcc" +
            "281d7257d5920000000200000020a949780c7af9ab3723ed8fbb343e810550b71a89b824572513da270252d7a8bb0000" +
            "00000000002027f6ad59ea316cf81ea5c5b929c766ef24600854ff4d92b81f91fd82119e7b8200000006000000000000" +
            "00000000008101010100000000000000209ecae2d618a5237ea180e04a6b189176360e1d8ad13ad6c8381b0cc244be00" +
            "e8000000010000000000000083010101000000010000002014cae4d344f5f84aaff20c6d401004d217688be3bc5fed3f" +
            "36738abf6f922b0900000002000000000000008701010100000002000000209c4396f9468333b686a42a14eb9341c490" +
            "9b61448f98dbe5b91d16b345490ae100000003000000000000008f0101010000000300000020f3fa114a95021c684db2" +
            "a3a04a74369b99ce774b94f67c53afa9e7081d42543000000004000000000000009f010101000000040000002026c6f4" +
            "10dd29398ee55090c47e4378961117420bcbd7d98b50e1daf94a3b69050000000500000000000000bd01000100000004" +
            "000000206961b6bb2720dcddc5b8a371ed9aa5f8d7ca0c969d011269b545050443739787000000010000000600000006" +
            "00000020f0b182c18e53e9744547cea840b40ec8a583b688bab7d3d8caade9de37edb1840c4082bad0f5abcad618694a" +
            "00bfd0fc66953cb884e1efda308f3bc550a92baf";

        private const string Sha256H7I21Root = "318b7e492064b91da9965c7dbd154b19c924c75e4da0440faecafe1fd2cf0bf6";
        private const string Sha256H7I21Encoding =
            "424453000000000100000007000000030000007f0000001500010000000700000020318b7e492064b91da9965c7dbd15" +
            "4b19c924c75e4da0440faecafe1fd2cf0bf60000000700000000000000201585a7693a28bf94d1be4a5ab8abe2bca110" +
            "c764671161424e6001b0091945c200000001000000203a13b5ffb8444420ed3129d549b8128b19313fc769b81d6ebeb3" +
            "910d9d3cd98200000002000000206e06787015a3b3c772c64a75a415479c9e8791d7c30636312bf7e63b6fe3f0540000" +
            "00030000002038e66c578f3affa0384d0d37e034c6ba8ec0da607869aff741fe970d93b411890000000400000020f287" +
            "4d44455b127025c0aa718567ee143c959b2ad5a00961112c640413a7fe650000000500000020d86acbd184639d98f363" +
            "c9807663fb4a8dd575ca14ab1c3c84c99cfb54342ae70000000600000020f0b182c18e53e9744547cea840b40ec8a583" +
            "b688bab7d3d8caade9de37edb1840000000200000004000000030000000400000020d77abe569ccd335a57e8a6096efb" +
            "7b9ec2b84196162d3e5c00a41b1d47e095f90000000400000020ceba31d56b8aab2aaa57e678db60f9675008354011aa" +
            "20b6857f911d728d31c200000004000000209aa80635008ba716d7d6eaf3bdcbe197d411daccde2163bd0e6416c45923" +
            "bd6e00000005000000010000000500000020abd123fe4e8b476cf948e6514ec59937586c0d14f4a4f476386f8206d13b" +
            "6de2000000000000000400000000000000000000001701010100000000000000209060f1a28478bd6db1dcd4e505578e" +
            "c8c86ef7d00bdd5b1a2c45abd0c060367600000001000000000000001b0101010000000100000020901ae6a7989c7760" +
            "527f094da19a43c204f0d337182495740b1c67a996eb117b00000002000000000000001f010101000000020000002097" +
            "f5da223d5d27e092a81039152f51c6f3c6976c9550134a6a42642700bc91680000000300000000000000290100010000" +
            "00000000002004da7027ec57a691ed6498620fc1bb3d914df1d57f6e22c8e20a382d6ee06bd500000003000000000000" +
            "00000000002015aae165d9195ad240b7f453bff52c0283933a1d7a7d255ad8653ea158c8cd0700000002000000020000" +
            "00208554365826d74ffbf2d43c885042e05c403de56c1e11658a0aaddc5602a83ca8000000040000000400000020315a" +
            "a66fc8635e2a2945d100f5f50cfc9c7cf2ca2b1127b17f6dcbd4d22e6d489b2956b97584cde27f4f7d275e5b31184ab1" +
            "cfc7c354a4230957257d7cd0a178";
        private const string Sha256H7I21NextEncoding =
            "424453000000000100000007000000030000007f0000001600010000000700000020318b7e492064b91da9965c7dbd15" +
            "4b19c924c75e4da0440faecafe1fd2cf0bf60000000700000000000000209060f1a28478bd6db1dcd4e505578ec8c86e" +
            "f7d00bdd5b1a2c45abd0c06036760000000100000020dfbee072d17d2125ee77cbee01f278814ef8fcabac7c59473d7c" +
            "ca7d75ed83cc00000002000000206e06787015a3b3c772c64a75a415479c9e8791d7c30636312bf7e63b6fe3f0540000" +
            "00030000002038e66c578f3affa0384d0d37e034c6ba8ec0da607869aff741fe970d93b411890000000400000020f287" +
            "4d44455b127025c0aa718567ee143c959b2ad5a00961112c640413a7fe650000000500000020d86acbd184639d98f363" +
            "c9807663fb4a8dd575ca14ab1c3c84c99cfb54342ae70000000600000020f0b182c18e53e9744547cea840b40ec8a583" +
            "b688bab7d3d8caade9de37edb1840000000200000004000000030000000400000020d77abe569ccd335a57e8a6096efb" +
            "7b9ec2b84196162d3e5c00a41b1d47e095f90000000400000020ceba31d56b8aab2aaa57e678db60f9675008354011aa" +
            "20b6857f911d728d31c200000004000000209aa80635008ba716d7d6eaf3bdcbe197d411daccde2163bd0e6416c45923" +
            "bd6e00000005000000010000000500000020abd123fe4e8b476cf948e6514ec59937586c0d14f4a4f476386f8206d13b" +
            "6de200000000000000040000000000000000000000190101010000000000000020f70be51682e353b4719ac70c4fc2e0" +
            "ba4f1c6309792b18d3199c13f036aff1dd00000001000000000000001b0101010000000100000020901ae6a7989c7760" +
            "527f094da19a43c204f0d337182495740b1c67a996eb117b00000002000000000000001f010101000000020000002097" +
            "f5da223d5d27e092a81039152f51c6f3c6976c9550134a6a42642700bc916800000003000000010000002a0100010000" +
            "00010000002030a66c272567dab69b13d569a0e2e25afb83e41481a9e830e07a6a5c59da50e600000002000000020000" +
            "0002000000208554365826d74ffbf2d43c885042e05c403de56c1e11658a0aaddc5602a83ca800000004000000040000" +
            "0020315aa66fc8635e2a2945d100f5f50cfc9c7cf2ca2b1127b17f6dcbd4d22e6d4879205b1710aad80bb58174b179b2" +
            "892f5f7cedd34e8ad406b3e7d0517a750ee5";

        [Test]
        public void EncodingMatchesJava_Sha256()
        {
            CheckAgainstJava(new XmssParameters(4, NistObjectIdentifiers.IdSha256), 5, Sha256H4I5Root,
                Sha256H4I5Encoding, Sha256H4I5NextEncoding);
        }

        [Test]
        public void EncodingMatchesJava_Shake256_192()
        {
            CheckAgainstJava(new XmssParameters(6, NistObjectIdentifiers.IdShake256Len, 24), 11,
                Shake256192H6I11Root, Shake256192H6I11Encoding, Shake256192H6I11NextEncoding);
        }

        /// <summary>
        /// A height 8 state at index 125 holds three nodes on its stack, so the order the stack is written in is
        /// part of what is compared.
        /// </summary>
        [Test]
        [Explicit] // slow: ~18s
        public void EncodingMatchesJava_Sha256_StackOrder()
        {
            CheckAgainstJava(new XmssParameters(8, NistObjectIdentifiers.IdSha256), 125, Sha256H8I125Root,
                Sha256H8I125Encoding, Sha256H8I125NextEncoding);
        }

        /// <summary>
        /// A height 7 state (k = 3) at index 21 keeps three nodes and retains at two heights, three nodes deep at
        /// one of them, so the order of both maps and of a retain queue is part of what is compared.
        /// </summary>
        [Test]
        public void EncodingMatchesJava_Sha256_KeepAndRetainOrder()
        {
            CheckAgainstJava(new XmssParameters(7, NistObjectIdentifiers.IdSha256), 21, Sha256H7I21Root,
                Sha256H7I21Encoding, Sha256H7I21NextEncoding);
        }

        /// <summary>
        /// A Java encoding decodes, re-encodes to the same bytes, and once its digest is named advances to the
        /// state Java advanced it to.
        /// </summary>
        [Test]
        public void JavaEncodingDecodesAndAdvances()
        {
            XmssParameters p = new XmssParameters(4, NistObjectIdentifiers.IdSha256);
            byte[] publicSeed = Seed(p, 0x00);
            byte[] encoding = Hex.Decode(Sha256H4I5Encoding);

            Bds decoded = BdsStateCodec.DecodeBds(encoding, publicSeed);

            Assert.AreEqual(5, decoded.Index);
            Assert.AreEqual(15, decoded.MaxIndex);
            Assert.IsTrue(Arrays.AreEqual(encoding, BdsStateCodec.Encode(decoded, publicSeed)));

            decoded.Validate(p, 5);
            decoded.ValidateRoot(Hex.Decode(Sha256H4I5Root));

            Bds next = decoded.WithWotsDigest(p.TreeDigestOid, p.TreeDigestSize)
                .GetNextState(publicSeed, Seed(p, 0x80), new byte[32]);

            Assert.IsTrue(
                Arrays.AreEqual(Hex.Decode(Sha256H4I5NextEncoding), BdsStateCodec.Encode(next, publicSeed)));
        }

        [Test]
        public void SerializeAndDeserializeDispatchOnTheEncoding()
        {
            XmssParameters p = new XmssParameters(4, NistObjectIdentifiers.IdSha256);
            byte[] publicSeed = Seed(p, 0x00);
            byte[] encoding = Hex.Decode(Sha256H4I5Encoding);

            Bds state = (Bds)XmssUtilities.Deserialize(encoding, typeof(Bds), publicSeed);

            Assert.IsTrue(Arrays.AreEqual(encoding, XmssUtilities.Serialize(state, publicSeed)));

            // a map magic in front of what is asked for as a single state
            byte[] mapMagic = Arrays.Clone(encoding);
            mapMagic[2] = 0x4d;
            Assert.Throws<IOException>(() => XmssUtilities.Deserialize(mapMagic, typeof(Bds), publicSeed));

            // no magic at all: Java would hand this to its legacy object-serialization reader, which is not ported
            byte[] noMagic = Arrays.Clone(encoding);
            noMagic[0] ^= 0x01;
            Assert.Throws<IOException>(() => XmssUtilities.Deserialize(noMagic, typeof(Bds), publicSeed));

            Assert.Throws<ArgumentException>(() => XmssUtilities.Serialize("not a state", publicSeed));
            Assert.Throws<ArgumentException>(() => XmssUtilities.Serialize(null, publicSeed));
        }

        /// <summary>
        /// Every proper prefix of an encoding is refused with an <see cref="IOException"/>, both as it stands - the
        /// checksum stops it - and with the checksum recomputed over the prefix, which takes it past the checksum to
        /// the reader, which has to run out of data with an <see cref="IOException"/> as well.
        /// </summary>
        [Test]
        public void TruncatedEncodingsAreRefused()
        {
            XmssParameters p = new XmssParameters(4, NistObjectIdentifiers.IdSha256);
            byte[] publicSeed = Seed(p, 0x00);
            byte[] encoding = Hex.Decode(Sha256H4I5Encoding);
            int bodyLength = encoding.Length - 32;

            for (int len = 0; len < encoding.Length; len++)
            {
                byte[] prefix = Arrays.CopyOfRange(encoding, 0, len);

                Assert.Catch<IOException>(() => BdsStateCodec.DecodeBds(prefix, publicSeed), "prefix " + len);
            }

            for (int len = 0; len < bodyLength; len++)
            {
                byte[] rechecked = WithChecksum(Arrays.CopyOfRange(encoding, 0, len), publicSeed);

                Assert.Catch<IOException>(() => BdsStateCodec.DecodeBds(rechecked, publicSeed), "body " + len);
            }

            Assert.Catch<IOException>(() => BdsStateCodec.DecodeBds(null, publicSeed));
        }

        /// <summary>
        /// Trailing data inside the checksummed body, and every single-byte change to the body with the checksum
        /// recomputed, is either refused with an <see cref="IOException"/> or decodes to a state that still passes
        /// the structural checks - never anything else.
        /// </summary>
        [Test]
        public void RecheckedBodyCorruptionsFailCleanly()
        {
            XmssParameters p = new XmssParameters(4, NistObjectIdentifiers.IdSha256);
            byte[] publicSeed = Seed(p, 0x00);
            byte[] encoding = Hex.Decode(Sha256H4I5Encoding);
            byte[] body = Arrays.CopyOfRange(encoding, 0, encoding.Length - 32);

            byte[] trailing = WithChecksum(Arrays.Append(body, 0x00), publicSeed);
            IOException e = Assert.Throws<IOException>(() => BdsStateCodec.DecodeBds(trailing, publicSeed));
            Assert.AreEqual("unexpected data at end of BDS state", e.Message);

            foreach (byte flip in new byte[]{ 0x01, 0x80, 0xff })
            {
                for (int i = 0; i < body.Length; i++)
                {
                    byte[] corrupt = Arrays.Clone(body);
                    corrupt[i] ^= flip;
                    byte[] rechecked = WithChecksum(corrupt, publicSeed);

                    try
                    {
                        BdsStateCodec.DecodeBds(rechecked, publicSeed).Validate();
                    }
                    catch (IOException)
                    {
                    }
                }
            }
        }

        [Test]
        public void EncodingSizeBounds()
        {
            Assert.Throws<IOException>(() => BdsStateCodec.CheckEncodingSize(null));
            Assert.Throws<IOException>(() => BdsStateCodec.CheckEncodingSize(new byte[7]));
            BdsStateCodec.CheckEncodingSize(new byte[8]);
            BdsStateCodec.CheckEncodingSize(new byte[4 * 1024 * 1024]);
            Assert.Throws<IOException>(() => BdsStateCodec.CheckEncodingSize(new byte[4 * 1024 * 1024 + 1]));
        }

        private static void CheckAgainstJava(XmssParameters p, int index, string root, string encoding,
            string nextEncoding)
        {
            byte[] publicSeed = Seed(p, 0x00);
            byte[] secretSeed = Seed(p, 0x80);

            Bds state = new Bds(p, publicSeed, secretSeed, new byte[32], index);

            Assert.AreEqual(index, state.Index);
            Assert.IsTrue(Arrays.AreEqual(Hex.Decode(root), state.Root.GetValue()));
            Assert.IsTrue(Arrays.AreEqual(Hex.Decode(encoding), BdsStateCodec.Encode(state, publicSeed)));

            Bds next = state.GetNextState(publicSeed, secretSeed, new byte[32]);

            Assert.IsTrue(Arrays.AreEqual(Hex.Decode(nextEncoding), BdsStateCodec.Encode(next, publicSeed)));
            // the state it was taken from is not moved by it
            Assert.IsTrue(Arrays.AreEqual(Hex.Decode(encoding), BdsStateCodec.Encode(state, publicSeed)));
        }

        internal static byte[] Seed(XmssParameters p, int start)
        {
            byte[] seed = new byte[p.TreeDigestSize];
            for (int i = 0; i < seed.Length; i++)
            {
                seed[i] = (byte)(start + i);
            }
            return seed;
        }

        /// <summary>
        /// The body with the checksum the codec puts after it: SHA-256 of the public seed and the body.
        /// </summary>
        internal static byte[] WithChecksum(byte[] body, byte[] publicSeed)
        {
            Sha256Digest digest = new Sha256Digest();
            digest.BlockUpdate(publicSeed, 0, publicSeed.Length);
            digest.BlockUpdate(body, 0, body.Length);

            byte[] result = new byte[body.Length + 32];
            Array.Copy(body, 0, result, 0, body.Length);
            digest.DoFinal(result, body.Length);
            return result;
        }
    }
}
