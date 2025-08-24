using System;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
	[TestFixture]
	public class Srp6Test
		: SimpleTest
	{
	    private static BigInteger FromHex(string hex)
	    {
	        return new BigInteger(1, Hex.Decode(hex));
	    }

        private readonly SecureRandom random = new SecureRandom();

	    public override string Name
	    {
	        get { return "SRP6"; }
	    }

	    public override void PerformTest()
	    {
            rfc5054AppendixBTestVectors();

            testMutualVerification(Srp6StandardGroups.rfc5054_1024);
            testClientCatchesBadB(Srp6StandardGroups.rfc5054_1024);
            testServerCatchesBadA(Srp6StandardGroups.rfc5054_1024);

            testWithRandomParams(256);
            testWithRandomParams(384);
            testWithRandomParams(512);

            rfc2945MessageVerify();
            
			rfc2945TestVectors(
                new Sha1Digest(),
                "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3",
                "02",
                "alice",
                "password123",
                "beb25379d1a8581eb5a727673a2441ee",
                "7556aa045aef2cdd07abaf0f665c3e818913186f",
                "94b7555aabe9127cc58ccf4993db6cf84d16c124",
                "7e273de8696ffc4f4e337d05b4b375beb0dde1569e8fa00a9886d8129bada1f1822223ca1a605b530e379ba4729fdc59f105b4787e5186f5c671085a1447b52a48cf1970b4fb6f8400bbf4cebfbb168152e08ab5ea53d15c1aff87b2b9da6e04e058ad51cc72bfc9033b564e26480d78e955a5e29e7ab245db2be315e2099afb",
                "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
                "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
                "61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b",
                "bd0c61512c692c0cb6d041fa01bb152d4916a1e77af46ae105393011baf38964dc46a0670dd125b95a981652236f99d9b681cbf87837ec996c6da04453728610d0c6ddb58b318885d7d82c7f8deb75ce7bd4fbaa37089e6f9c6059f388838e7a00030b331eb76840910440b1b27aaeaeeb4012b7d7665238a8e3fb004b117b58",
                "ce38b9593487da98554ed47d70a7ae5f462ef019",
                "b0dc82babcf30674ae450c0287745e7990a3381f63b387aaf271a10d233861e359b48220f7c4693c9ae12b0a6f67809f0876e2d013800d6c41bb59b6d5979b5c00a172b4a2a5903a0bdcaf8a709585eb2afafa8f3499b200210dcc1f10eb33943cd67fc88a2f39a4be5bec4ec0a3212dc346d7e474b29ede8a469ffeca686e5a",
                "017eefa1cefc5c2e626e21598987f31e0f1b11bb",
                "3f3bc67169ea71302599cf1b0f5d408b7b65d347",
                "9cab3c575a11de37d3ac1421a9f009236a48eb55"
                );

            rfc2945TestVectors(
                new Sha256Digest(),
                "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3",
                "02",
                "alice",
                "password123",
                "beb25379d1a8581eb5a727673a2441ee",
                "1a1a4c140cde70ae360c1ec33a33155b1022df951732a476a862eb3ab8206a5c",
                "65ac38dff8bc34ae0f259e91fbd0f4ca2fa43081c9050cec7cac20d015f303",
                "27e2855ac715f625981dba238667955db341a3bdd919868943bc049736c7804cd8e0507dfefbf5b8573f5aae7bac19b257034254119ab520e1f7cf3f45d01b159016847201d14c8dc95ec34e8b26ee255bc4cb28d4f97e0db97b65bdd196c4d2951cd84f493afd7b34b90984357988601a3643358b81689dfd0cb0d21e21cf6e",
                "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
                "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
                "61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b",
                "439b7630ec82c94d3bbd466a068d663a40b8d5b1d9b006ba43f5d715498088cca8547bbe3de6406c79f15ffa7356bc93580e478322daf8b2d014347859234f01555c457ab8b7f214875224fc9bfd07a68f37bad4d74bc8467ce10ea39301d3604e91fff5f881d52c558187e68fac3268df2897307da5c58a8c667e0fa8dc837e",
                "c557af6030c3df27b4704462df2eceaeaed5d16b4c7d87fdf992e282f985293e",
                "7094d74b440ea4bffa2752694f19600268d61893ad55cac759a18378dce55020742df26f9696515482626372af87d44788d931e60ba0d4d8b31984b30ba285d5db443753ade4504ae124eb63d16db568e6850adf953b353c1255e8ec230e59a904f3784002845a31d12d8f448dd6d1bc3ecded0bba328046b907546f9e3b338c",
                "febac740e997507c1c7df7690bac49a97f84ecda99ceb047c575b58e160c477b",
                "51d0af1793f2921cfc4a41bc5134605a7bf89a3497aed7c29ed6c56ae709037f",
                "2f6b44340bf8dc05148b6b3ae1d70b6a896588ba6b2c16d8aec619d2cc57653f"
                );

            rfc2945TestVectors(
                new Sha384Digest(),
                "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3",
                "02",
                "alice",
                "password123",
                "beb25379d1a8581eb5a727673a2441ee",
                "4ce935f41c1695fc8626b436a28efbc0b887bd3b280bccbf4a85efb9db3e5a9d56f52e59d9847650b27522b3d050389b",
                "f41232a98d92134d9ea5cbc890f4ae7d79f9a744e8713fdd8285b4ae87005fd009542f6b0a2c65fdd0354892fc1c6022",
                "4c06965cf41b74644efe3ea5d8d7d02e9155063a9323e6255013c4ef55500ccd385c0458a571cbf6b626e2fc166f0d2e62ed06fc2bb1bbf04193d8028f4f227f8e8516e7afe17dddc5f492d6183a73c4eb64a94d53def53aed62e7989eebeefa23420b73008df74f3e0adef67a28c87a2f03d22beda3355d4d200b2bb248b727",
                "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
                "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
                "61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b",
                "b31489c905db003ded83e9861613df9d72f28a738e4baeb0e10c7f67faa51ed230d87e8d13aaf15e39dd9f8a5d43335570c7c56412495a257d12d3aa5b6fb76c912af20498935b6bb8340102695756d72267e81bf3ad169f4b89ce499b7502327471dddf9b8fa145c1ac6cfcdc32e6ee715dd1f8a9f589db21784cede4b6feab",
                "9b7b51de2fb39c074834dfc1436194f4e4f391e999249185faa54244ab8084c3e4e7c4c077b2e1f68f2f7af1cd8c76ac",
                "d8dc67c68957a19d8cc45a0979477f50cfa149fb8dbd8bc4520523fd6d9658bc4fe269d5531a3e14b410d96e3ea15de233e57efce49f90306bbc25c24eaf94cdd97e6f2e29c5ddeb1e9617f4c76adc0a17d63c34f8b408d296121a8533b9437372e5eee78834727d4e1d2ed06da4de24d9ce844a8fdfb5e8d9c4a9bfd1e8ebda",
                "70896daa45cc0d19363592bf064a56c8ea6f389ba2750b7e273e0df0f9c8465954b7c98fc12b3b4d17c54433a7af84be",
                "7e0bf4b137cc169d74a30ab0ae99f150f11db8c711504d7381a68de487dc065e115e2594de7995e3494b23815a603a5e",
                "ce2c76795a226ca9f2a52d2113f4d067b46fc9b761d7970626fdc505e390996dd6973a55ff4862b197b9f2b2b1358523"
                );

            rfc2945TestVectors(
                new Sha512Digest(),
                "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3",
                "02",
                "alice",
                "password123",
                "beb25379d1a8581eb5a727673a2441ee",
                "5df1c7a41b6eeb64e6eb12cc8bcc682be86f5b33be6a80b607421b436a613adedd13f8c58f216e78ae53b378e9bbce1fcb48ef8d1870c11394df228c7821d27f",
                "b149ecb0946b0b206d77e73d95deb7c41bd12e86a5e2eea3893d5416591a002ff94bfea384dc0e1c550f7ed4d5a9d2ad1f1526f01c56b5c10577730cc4a4d709",
                "e714706a2a6c6c0478444006a15ea8625943abdfa2c0ac9085cb174623304b71a55fd9a4114e089a05cd0e898b48294b6c842b333ce8141afce3fa54dd8d0ed6a950642ab0066858456219f88038d68fc4affcaabfec4044ba484719addf2fe31ab5f02bbcaac55b5765fb1827d9e7de8150c5ba6c891da9cbbe1b31f3b70b3f",
                "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
                "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
                "61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b",
                "27f876cfb2079a4eaeb6a54407e212362a122d727fbe987be5e094baf3de39549f48559040f786028364d93264258c07aa33e65951147a87a2a6c256c9a9d137eda62f6ea1485ce3f5da4e7833c2a14fa25d32376a5c08c5e5ec5a18952f966b43759280edfbb4474e3c88b87cd0c2d2eb3b863219fd2e7e382d459d3b9c702c",
                "2f0e11f9b9dbaf5a6b62b77c6a8febf2f095e881a1f93fe2ce97b6858347e4f30d2e7581e88ae02955555ea6eb36bb9f8bf3f350d01ac13e79e0304d07d7bf00",
                "b91800202d0fb90ddee952e8d8bd3276530f0f73f0e9f7a73315bf477d7b208fc5e452d261db645c16f62e3b9b8cc9f43a45b99b384be5a55fe13273039893a39d051ac4926b9d27f4a696b867ce23e8a342bd770a059e6a306828032a712fe6254d690205931019a4009c050767b7c422eba948797deb05b6c61e0398499812",
                "9c1a239c705b4cf5715bc9056b67794d3762ed1112f5bbaa7ca64ae4302f4ec9c9523e55908c67bdcb1b82b4ffc1e1c81b44d4d3f5e0661d00add4fe0175e377",
                "aec208b9685a2aa51b2aba924b907d43d086757f82f6cad0ccd301cc134280c221a50f9a7f8e548cb3791914cb625f1527762fcc08306bde01110e1b4d78afc0",
                "9f8928dba630ac81412c3b80a0317c728471639b788ac5cca90441bac62cc8ce0e60a0f8a0e9b2f517068809e64d04cc9e54e270b2a28a45e9541c43543f20cc"
                );

            rfc2945TestVectors(
                new Sha1Digest(),
                "9def3cafb939277ab1f12a8617a47bbbdba51df499ac4c80beeea9614b19cc4d5f4f5f556e27cbde51c6a94be4607a291558903ba0d0f84380b655bb9a22e8dcdf028a7cec67f0d08134b1c8b97989149b609e0be3bab63d47548381dbc5b1fc764e3f4b53dd9da1158bfd3e2b9c8cf56edf019539349627db2fd53d24b7c48665772e437d6c7f8ce442734af7ccb7ae837c264ae3a9beb87f8a2fe9b8b5292e5a021fff5e91479e8ce7a28c2442c6f315180f93499a234dcf76e3fed135f9bb",
                "02",
                "alice",
                "password123",
                "beb25379d1a8581eb5a727673a2441ee",
                "815a4561e1a68b3fb7f6c03bbb3daaa35d528d90",
                "94b7555aabe9127cc58ccf4993db6cf84d16c124",
                "661b6fea4bbe1a09df5a17a9adf65d8ae890aa2f2ea450efb5200a5c5dae98fa2ff0677ebb8c70012cc41b344a18d10c79a64a7ac6b392db99e0c8f16d7a50adbe2955103dd38e5c5a287da9f4264cf93fedff3aa6ce47f18a53ec41ea2e7bf36c53de4b223266558dc0e6ddec513e059b0879112637c7edca8516338a4b5acf4d634133db26ba80870b1eb342ad68c956f71a03171d23a76a4c735199027155b40103caecc131ded02a2664c4e17a0aad2b204d600bb9bbdab7387b130c00dd",
                "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
                "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
                "6dc951a17f41ab362936a100f0dc2167fcdb76c537a2788fcb201cda999556cfb20fbfc29d3a108dad2e7edd7f82f2fdda964351e509aff3002837f4afa676630c2ce9192d69def5a8452804b0e32a37659396c39c2a2d114a3cab02ab70fca321224049c5f4d13dc0bc810143832ea6d78e5b3be5497afbe27dfd76d01e8f649437637eacb376fa08d31a759041362fc682408864925c02bbb0ca9bb5342bbc3c686dddcccbb65b24e1ba745f50a8ce91cf779586a811a39eea12f8063192e1",
                "314614582b28534282b61d2c89814558d6081be22453fe211121a020d672775086771fc444daaedceb8a94acaadbf0995329959f29c87525c72045c89af70b5f47c120525c9ea5444344554c5dc18f16a00ecd5e6180230416fe52264e91cd6586c46f538644b49477cce705d43e5c3cfcc64b21562666298d87eb5798e891dbd575d7e30e01af4934c0c66ae0b73b6d7514948433214547d347e3405fdd38326b047b9f776d0dd7b7a47574fb3de3c637c007c7ee8357e182872daf47e4af12",
                "d34e6d8aef7c136a7cf831b140b0f51f19c3def5",
                "71463717c0c5e9b014df2f53147fda925567066585edcf3b97af5e105f47790956ff32b563346d6f409c64124bb6350f98bfaeb9be83ad3b5392e4e3fb32f4a6bd4798c4b0f3f6bef9ce4cfb027f80e3b912167b05f40bb8c5990e97da03d2c28de1a4f70ecbb725e9a5ed0bb0303fc09fb424e06dcca8fd8b9da7ed54bbdce815c4e48bf43e5746e1cd577f95189b3951f37ed428d76242771399e30e2c47b0a4889b391ccef09bb9039ea544584fb3e9debd241883193c64a8ed9d9719f7ee",
                "06659e64e5d1402dc3b90f108e8cd430ab3da6d5",
                "9f47359ca82de1c55d04f55f81c14914a1512895",
                "1a0601206490765baa7c8f684411ef7411e120a0"
                );

            rfc2945TestVectors(
                new Sha256Digest(),
                "9def3cafb939277ab1f12a8617a47bbbdba51df499ac4c80beeea9614b19cc4d5f4f5f556e27cbde51c6a94be4607a291558903ba0d0f84380b655bb9a22e8dcdf028a7cec67f0d08134b1c8b97989149b609e0be3bab63d47548381dbc5b1fc764e3f4b53dd9da1158bfd3e2b9c8cf56edf019539349627db2fd53d24b7c48665772e437d6c7f8ce442734af7ccb7ae837c264ae3a9beb87f8a2fe9b8b5292e5a021fff5e91479e8ce7a28c2442c6f315180f93499a234dcf76e3fed135f9bb",
                "02",
                "alice",
                "password123",
                "beb25379d1a8581eb5a727673a2441ee",
                "b2286eee1033fe2bdc950cbf0abb6fb56670e2b4d5bda4cb203a9a96d018625d",
                "65ac38dff8bc34ae0f259e91fbd0f4ca2fa43081c9050cec7cac20d015f303",
                "2ede0a454062630d09063a0e6b5f1cb469ab9e1a1d937d8d65d68b4aa007033bfd08d12e2ae5a176d15261a0cf7b8e14cfb39554a3132d10d6b5b3446d918e98945a8fe81f79cfd3b214961a6d085cd8228208c66933eb8a4af3f0789a8d5ee43ec3a6a201f4771898ac09ae9867e03670b3524fe182a3b2caaa5521af1199444fb47ee3ed7037cafaae847cd8c92700eaa862224e01b6ed0761b35cde0b4d177d314648c466f026b3408ef151f6eface89b13688652791203744a8fa93a4fcd",
                "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
                "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
                "6dc951a17f41ab362936a100f0dc2167fcdb76c537a2788fcb201cda999556cfb20fbfc29d3a108dad2e7edd7f82f2fdda964351e509aff3002837f4afa676630c2ce9192d69def5a8452804b0e32a37659396c39c2a2d114a3cab02ab70fca321224049c5f4d13dc0bc810143832ea6d78e5b3be5497afbe27dfd76d01e8f649437637eacb376fa08d31a759041362fc682408864925c02bbb0ca9bb5342bbc3c686dddcccbb65b24e1ba745f50a8ce91cf779586a811a39eea12f8063192e1",
                "66078c6b792c6194ae3b7033454acb96cb9cd02b4d6854dc51bb2218390c177d2b03e9a2649daf835153954d8dca0423f3742b968188621a40bdeea83391e2fc026f014838a171d80b04e01d24517f1a068e71ef7bdda01d9dcabd13d5dc5e6be8ef9fa4af6f9bfc6931670e609b6486d4ce7a60bf1b65e83aeb631605972f50ef6bad04c2cfb0ea756d63f868085516a35d3bcb3268cdb3c0cd25721bde95dd8011950b3bd39f3b61fcc2b30062c71ebb78530e4b7403a9480eef00c25074e9",
                "60a2ed1442bf731114da0fd873d70950c0005f1e4c56c52821756e680cb7bedd",
                "6110bc37cc8e2582a68cb758370620da67ac8bd1bdd62503665e863198b5120fa68534f1956ce549ef3b781c410ec256572018087939633ac9403b81916b44a286e41fe11f4f609a5a1d4af672cb73b87e5189b2c9bf707d215499029febbe66faf057e5f64652b1ffd970a5c9cb185605cb46fe0d02faa8d7c170cfc2123bc186475f74e5d477efa9fd4d3b6bffa05280a98bc6e697b7d687e9e58ff7ad7b61dfd56d39cb89adff552e4b20dcb4e9d3300b0d91af9ab463f0f2a9f279744b09",
                "887452cd0318b4196062497c9219987ae5f0bac6139b4a629629f5216cace376",
                "a52a4a217b4541a021a5731b68ff2675c68cb36504e010c3a3cbcf97844d092f",
                "2dc1ea113ef357884c236aeb36e1d9f48c3ca83a41826086b78604d3a36236f5"
                );

            rfc2945TestVectors(
                new Sha384Digest(),
                "9def3cafb939277ab1f12a8617a47bbbdba51df499ac4c80beeea9614b19cc4d5f4f5f556e27cbde51c6a94be4607a291558903ba0d0f84380b655bb9a22e8dcdf028a7cec67f0d08134b1c8b97989149b609e0be3bab63d47548381dbc5b1fc764e3f4b53dd9da1158bfd3e2b9c8cf56edf019539349627db2fd53d24b7c48665772e437d6c7f8ce442734af7ccb7ae837c264ae3a9beb87f8a2fe9b8b5292e5a021fff5e91479e8ce7a28c2442c6f315180f93499a234dcf76e3fed135f9bb",
                "02",
                "alice",
                "password123",
                "beb25379d1a8581eb5a727673a2441ee",
                "185be3649ee0c808c9470903040f72d3d9d8470133d9b7eeef3e72d3c4e308bd63b594a159fe4b8a3ccd3ca3a54176bd",
                "f41232a98d92134d9ea5cbc890f4ae7d79f9a744e8713fdd8285b4ae87005fd009542f6b0a2c65fdd0354892fc1c6022",
                "2e4a025277883ed3040ee13534b24d7722a1a8449ad872d89af0fd317e93042c66398d2bdb5e8a7ad8f13891aa4044629ef571c11e38be69cbb42d711389e89a9b7ee98565fa9b66cb0d0e99793855969250816bab57d6e0d612047a5560bdb29b5e447268064751387faeb56ec5d14eec048b50e0e53bb747bd59a723e4be4737472838b384c4a5f6615a00e554aad26632de3925bf472474f124ac41ded1dd7c56f7c1398329e35113a2f2e64dd7538048eaa756272103690d11a0e0bca397",
                "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
                "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
                "6dc951a17f41ab362936a100f0dc2167fcdb76c537a2788fcb201cda999556cfb20fbfc29d3a108dad2e7edd7f82f2fdda964351e509aff3002837f4afa676630c2ce9192d69def5a8452804b0e32a37659396c39c2a2d114a3cab02ab70fca321224049c5f4d13dc0bc810143832ea6d78e5b3be5497afbe27dfd76d01e8f649437637eacb376fa08d31a759041362fc682408864925c02bbb0ca9bb5342bbc3c686dddcccbb65b24e1ba745f50a8ce91cf779586a811a39eea12f8063192e1",
                "5015c18641b88349765b561ebc58ec0444455257a78c9672e811978bee81dc1841fd98cc89a141fd22b9146b09dd7654d3c76c0b684e4b0f434144ef2f48793b65aaf15e18da5eea6aeb4fb705528df82487c6ffb23fe23db85f4c48e65979deaeeabfed2b7253cd5c2947b2eecf5a9a7338d7ac2a2ddbc6ed026d3d18835fc791d1bce007dd020f7c11b964ca68c05892fe06443add24d26fb1eec1d47bd38482fa58586fe8e24ac01fbb94b2415540d7ef2f0833bcf9cf89993e419138b0ad",
                "3ba9c623d53a1952e8a379ce27bb78c6d1b374001f5cc9a687e5b6584bb65cd3b2c47640a3612d33b26ae15e85eff64f",
                "0d5f6d31ff21be41acf99d785121696c5bbe2f3d2d7ee98fd427a3bf393c4f2137a6291e5b78f97462bdac3f039adf49fa8dcac89207b74043eb42dac2d7479a8659e756bb8820c20253e7f13ec60ebcb64e2b9a660c3a24c55fcd9ec018d221780225a924304db2deefceb0e0cc51d5897277c5d50a4284da7fd58d78144cccb7abe72505b86ad2077825dc515a67486f32c0651ce72f7afe4c0f9065464236e656cfb9d40b5019493d65dce01571ba2a82eac81a8da24d37524555c4280852",
                "387747c1415b02fb279fdbf1e00ba50deb91f846fac950f536311d3702c9894a59908af9f41773737d6293b3cb6e95d7",
                "6a8f588856a931bf9b13954aa19703d46f0548b34b395b8e9982b382884c7c551c44d0b7ad44c6798693c704ee1c690a",
                "1d244931d861d537837958701d770ef91b1543ccfa92009419b3b3d67ca6a984c6dae60da2d869df9ea594612347fd92"
                );

            rfc2945TestVectors(
                new Sha512Digest(),
                "9def3cafb939277ab1f12a8617a47bbbdba51df499ac4c80beeea9614b19cc4d5f4f5f556e27cbde51c6a94be4607a291558903ba0d0f84380b655bb9a22e8dcdf028a7cec67f0d08134b1c8b97989149b609e0be3bab63d47548381dbc5b1fc764e3f4b53dd9da1158bfd3e2b9c8cf56edf019539349627db2fd53d24b7c48665772e437d6c7f8ce442734af7ccb7ae837c264ae3a9beb87f8a2fe9b8b5292e5a021fff5e91479e8ce7a28c2442c6f315180f93499a234dcf76e3fed135f9bb",
                "02",
                "alice",
                "password123",
                "beb25379d1a8581eb5a727673a2441ee",
                "ca60d3f7472505b7bb776abc7d9abbf6da88d419b85d30f5a29b2c039727138285eb66df5af2213a52f273866894d12083e9c23f54d0f26509386fc0cf64b150",
                "b149ecb0946b0b206d77e73d95deb7c41bd12e86a5e2eea3893d5416591a002ff94bfea384dc0e1c550f7ed4d5a9d2ad1f1526f01c56b5c10577730cc4a4d709",
                "359c7fa92ac9a8b86a92f3f47fa98c099c8a6ec5fbc9575ce52dc6f1f55d4f1f00c20bfaa88e0707e21ce1030ae122ab4cbc82be31254b49f235c3c303a6a8098e7e286396dce1cb21c55f4ede7543e4a8bf0be906396a227c2ff4bbdadb3161ea4f679a62edf155de2b1b67658a7b5c40368de48849ef88977e4e97da8fcb1cee8ff0cf8d9245683f766cb537d89d442bf2ccd65ed6fa2c9db4ca68a4d2e7558b428596ce7a32414cfeb592e3149a23287759105be8cde7cb739b08056f28db",
                "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
                "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
                "6dc951a17f41ab362936a100f0dc2167fcdb76c537a2788fcb201cda999556cfb20fbfc29d3a108dad2e7edd7f82f2fdda964351e509aff3002837f4afa676630c2ce9192d69def5a8452804b0e32a37659396c39c2a2d114a3cab02ab70fca321224049c5f4d13dc0bc810143832ea6d78e5b3be5497afbe27dfd76d01e8f649437637eacb376fa08d31a759041362fc682408864925c02bbb0ca9bb5342bbc3c686dddcccbb65b24e1ba745f50a8ce91cf779586a811a39eea12f8063192e1",
                "6847e692e55730ea0762417c9e66fcac0dbcb80b2fc56cf78b06c2e034f1f4569ae95743d4e986e09508f129288d0400884ddc26c84c7ab291be6dd3c1d5131247922c1409d61abbf006a86d61830f005745b8d54c6f7a70a6615644023e56fa75b0e733c221fb6d283a8bdb5280a1e19015f1fee7144e27c4305719178dd56cd64b88eecaa45302b359427fb36681b7e8b66b573e295476f092d6fbd6ceec8d2379d1efed605acc37dcd6ade601fea1540741c490548b172db8d2cf229fbcd3",
                "1f97ff810f3dbc0a58b5a27635b333a47d4d71f8db0f6b0fca494e26034e2b8e0f527259a678863bcc4732bb3d266b59c164fed36135e477b0438702933cd7bc",
                "6be159a25ac57de6eeb852173b0499c56a24d1cb31aacc6e595b572a2e8255e1984b4e0a2bff8658566f48f958afd9d07c188cf244a47148bd726f9527261292c0a72f8745814111668a58b2222f6c660272f2964ac547285571f93be30791fee8d97ccee743ba31d471a193ed6f96abc1ce207e2108da093cb9a74ca8a06cf04b5075581a9b057b4a1b50bde4310107314b45bf3eaeb409b45775fd708be2f1c8554e3f0916e1e5d5e19f30f9411901a961e7657547c829be75db3e07b1cca3",
                "379d2db8c29bfdf20103b9e948b66bace2d6c87ba01c745fc85c4c21cc52eb32df03c138011f3980b8a3d38e7e93196c791095dece212842f825f8fc08ba29d9",
                "93ebdecda29cb1e617e9f91b403232f04397e703b7414022b39938bec5b85c8135d492ef74e862a7ec3af8aa6bca8e97fe90fb952ef5d95d667cb9bb5e44cedc",
                "a6e8f884cb75866a38b64d86496a9d66ce7a2b7fc00077dc851c1754b3d1c0aca42a536ed78aa4eb8ec1b911c3873447a4cd6e07357bb02288c453332c4dc541"
                );

            rfc2945TestVectors(
                new Sha512Digest(),
                "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dcc4024ffffffffffffffff",
                "05",
                "alice",
                "password123",
                "beb25379d1a8581eb5a727673a2441ee",
                "e23815ed6634afd9f6c2efc31b593068347b5af87a072252a53f18019ccdb30e751c17ad439e1a65db22d67ef3c181cd806cdbba608718785707156f998c4198",
                "b149ecb0946b0b206d77e73d95deb7c41bd12e86a5e2eea3893d5416591a002ff94bfea384dc0e1c550f7ed4d5a9d2ad1f1526f01c56b5c10577730cc4a4d709",
                "93eb6be5abc880d776f9d0d1f44e51d9535c911a566eb0826776b3121fddf454246b40582dddc8a2474b0933054d5ec7857789e23ad906c34cff4b10fe4cc970640439bb5082c771dee6d47e3684446fc61222bbbc84dc9105a07e9dd94d40157ca1b3bc8d55f09bf771e42ae943e1f09ad160f954bae55e38e23c7df4777183d09f4324941ae5beab143cf7c4588b4c2d4e4256ccbf58da801c1c80549a8e816f1d3d2873de14023ffa126c079603cca98a8aaadab8ad194a62b265a996a55e0ea8d8e2de3c9f5fba26b6c6625b5ce260fe064d936b73fb35ed1e14f3d91527a44fd9f7ec00a903931f8fa2ac9a08032b2b8948156eed810f1ff23075c76314b0b5f1a04461b63ec100b731ea0ef2ece7563bda5c6fa19b67c7d83f02ff54edfc4695ea92528fd92dff960f3c50354263d30e8f46e43cda7d2c7e1760f4bce57f7014a7e989806e9168030798c168f71f0fb0563d9853f2539926161ac2aef0257c3d38ab789eec0598679361ed7090b6519ea204fc7af0dbd76e7ce0cca90b53a1768ad8340c1faf466b1f45960f92f60a8e2c82722166180773be5c9df2f3975ae7e1b9a2fd105251e031e91fc913c0bbe31a0baf51c0892452ef37980ddad48d2b4d461426f0c7aa1871e418a8de7f66e369ed2db257aafe0473205f736c767299335ecf0ba3330ed69183ee1957a7712452f166e02b0b976d786367c05a1c62175d59bbfe0754248d650ad0b61e8b8c2293a05cc99666256e740220052d809bf6a573011a01e3df8acd263d27eac83155fabe64a04f735fe26b7da939b3722b1e9a980c4c26a391f7224fce4628f20099259ac8e4e8216719fc66f8ae57119f2b579facc40b8eb3cd4bb8da7c9d3e847f93829e1658e2a98f0df2325e25940ed7fc9d75e7f84e3f6f729db90caf59ee5015ad626cde4eba09a929afbe34cce0841b469a022eeb0ff97e650378c64e75cb09b82bd0824952695ef026aa27f370be2fa75ea0e4f1bc80d072850f9647469e2203d7a1da6612e1f6729bc1973f7218531e5b17b27915f37840dcec69896accbafff05dbc75bebd6d2fdf2e05",
                "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
                "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
                "a271447b3d484bf77c779286d345b06f96e2545a1ec207958c620e51f5dcd428537528cc1bb5dd68ad753775d53f0f0d92a4aa8b59b80a159e1b23e1f219dea0331d361c8061a316df5478fe0a05a8d1ad2017a126b32ec0286dfa77fb7c1be913fea0e1605cb4402307a8614c36e7adf6711b3e8e4ca136675b7b40721dcba3d710acd18490ec841bdb09be3aec8b6dae69027b8125bc42ae6f5564c7dbbc3d0e660d48bc30f0830b246b1532b3f9c5bcf4a272d9f8edb9570df85b67467078f210e7b0b4e37cf6b447d1e07a11bf51a1018076856ac2eaf11961d1f56a3dbc10acd8c79733297e16b984ce41ac274066964e2cdd43680aca1d6804dfe6cf68ec746445c74190fb1cb1c03763a62c51fb422d29b139d4ec4577b7241fd6eac5a62e2f77a414b8006e6931db51088b62c25856210b677484f88c5668326df01df2c82ed39a9158203c4461be7d9427b9ddca1a577b105e926bb7d252be7d408f716f8c6a6c642e902b3c9a59f70dd523a5025d3b89c4fa66e2edea4d4215c77ec9e4ae8877b570ca39dbe46efbce8915c3e8fb48448d67dcd86e1e17c35f89f29ede148a7e0fb8a085ab58735f08ffa30b29062dc341429cad715237a86c4693e8b5268c38e1245dd99143f5fc4651ddc0366616309a3d99fb81e2e740f9c67ef6cfee417a696bd8d04c2cedd8b8a3a05cbcd314d81fc773004d6da8bc33bbfb04ddb17a0968c7ee9933332e28aff249c7bb98a05fd7d28a7c607d5ba9b3f87b3ebeaaab66f6c430c872c9298b1cd20c1ef0cdd2f2a415517be79973e0fc07a19f30bf23422e6c0065776f216fd3364e18798f05ce4df6c02f13e4d56d2e2b658ab3515c650970c626bfe7e91224cfc7943a4fcfb2b492ee693dd249e9619aeb6fce9c2043740097b3fe2f90a2b89b3aad05687d742d8c1818921e23754b769be2f5b33be8c8e779667d1e491fb462ef24c8a285b17d99c68b6f3d106ad976bfaad0ad74aacda01216cb07edc91db3e5a0536a8c83c4c10fc324e2b4ac7626d029b9f0002051d9907c5bed60d5993c5dcd04349d087d2f7ced9598f3a7e134f5",
                "9ce2c593321cb5105add07b50270725184fde28ffc252acdffe83b9942e8b16ea6d314d4e7c88578a9f61fa1add6a7d12526aa7b0b39d2e79c77d5e978ab3d315a3fdee159f49ee0a23dba15ff346d76ffe23610b1f81499d647280214bdcdcc7e887b805d9993d4773b188113220846516638b1616c380c6dab622f0a439a0ed5d9e35c8cefe63ecfed176466b4c8b25216b827f7de52e1978fb4857e7eb5deed7a6e0c54748893f8371ef0fdbe77a3f08aae7c430bcf56108eb613727afc58098f601802f545966c180f04c4b3fc6d84d8355881004bd221c2ebe4f28045cbc00035266f38331c2b05cce9924bc6ab50b24dd7c2f1511846d6e28a6fa662cb8d4f9c0ef32df3b83c9f9e684ce57085aa9e516c8d978ae6c692d40d99740b53fdc8d424f89a19ecdf4e902b2b8ed52fcc965924debb726e98a119e1b6b540eead53e81b19583cc5e113d60c0a8d45cb1d9a6fecf8b41dfecbef9242ea8eed010aacb2934cfe034f8cf792d4906e9b0c79c9cffcbacba251ddb4c30d75edd5e49ac4231f38502a8e56ecf4976d71e9a115143072e410797d1fa39cbcb3c6a16fc1e12034cfa919ddf8eea69858ea1a524c035e01c8cd95ddbb25e868e3632040a5eec84ea89289bfbd1711e3700fcdf741c00c493017598ce23bd604d3fe9b89045ed1a9cae85a4e969246b6ce86a1640a48f08f2035f6fd69a6973fb52ae7c65f94528bdaf04fadd52bb9ad3207bb77a0d783c909620849345d6151ab9ddcef4eb2b451cff4fbf2ac1b5fb1e62ed5021e2ff542badb0515cac96f62dd4c2e571ac9865f3f81ea5d90083cecf8d62d873d20e43f16a968a975bba650646dff56cad0d60c4693ea8d7996180b34c38cfa8795475f08fadbe093f0ec49b768d325f3efb591e6cf12097bdb7bed64c6c99bc9c00c18cac8bd4a7f12559c3343be68c78ed0652e16685b65dea635f504b868ea470a81e42d6b68b8a8452a78c28124bac2cb50296bf585cd5615f2a32943824a7397fb944f90bf4db6017c5c6911a30f05efa27a178996494ef2acf61da8322ceef5e4b18816c52368e8fb1d7d0aed",
                "2b74f812d1292c1440203fbe072f0addf0d2da3c7a47e3aa63fbf38e887750410d03ee766d4da4735a5f55bcbe1a7836a11736de0617ff4356d846b6c91a5b18",
                "e555a1c5e2bd4f853e5a0049f964a5348b44c7a53a7d7def41bbf5f6c5a6cfa96d113d9454b039157c14cfb6959e849e7031a7c2d8654308fd74ccc575f680e5700423d31ddc4944e9df7322ccc4d4eaed83fd3b9d063a4dfa2f2c80d24f4b679522241595656aa4d14d071840cd40c0a35de29bee70b57baa0571a65e30b8b9669670ed83b5aa0d46397a28f6cedbde5ff410b11446498636ef3d04992f9d63501c71d264649fe4b18d0b043e621d2ea4a260a9684fb1f28aaa0a81a1956ab0fec712d9f82d0a3f2d63c3230432a8f1c78e7258b6c76ac100bef784705317a44613e87db726015f67fb62f26214d7ab28a7fb979c191d94765d04b4b4f007e5a56af5fceb2a68b13833869c244d08ec8a50bca2feb31dfc863ceca7d1545163200d0570bede3700e9412412f77286ede2fa46df0118ad67cc1e90405d7f4e9cdd93c164c3fe233a5a5c1495d880c2a479b71c61bf17a1c03df391a3afb5990d9b0179da15ff3d12b542c40dcc9f3b72bc99c8797c34eead804b26decc299e21ba8b80558f82dfc8a2face85c7d96a7cead7c59a5a7da25f5efe37fd15a3b5f1151639f8e37423f0f315def914d179163f4c0d495282ffa9fe8cb8b5df49040bcec8419157a347c30e2139a77055408fa22935121a61f066ab1fa8cd039096aadd700491b2bd52a7c7c349cf1e3bb7acc6257152e2b7cf2e3bd7d8b8e49a31e27d583571899a5df30707ad4f55b60075c5f8014c3ce4dd005fbf216328b4f8e4e0a4c907c661b0432122ba992eb4dcf4a85a2225cf12c40a97c2f7d2457d1fa77b3eb892361381e4da0eda63d8d575e77e251efb17ac3efbf81a85f7cf3c04144aca8ab9210195b82604023fe3273246d251ef8d0902b4914baf5fbea17996a13ab2ed74baff06f160c9401294afa6d366f169a2a97f1961b3fab0683dfff98c6701120641f33cd1c44c8e8379bb7441d2830fa1356dbb8b123079f0a30166e4bb2a7a9337c73baa16710ded48cb32e12d0d515e62ba2590045758536a0052980aef572d60d9bb0a1b1c05e97c0e165d906fcca128fc09dacc517305e17fe240",
                "2ebee7f7d18fe54adcc24b7895e225905c611f9f94954e64518e82b27037fa66d7f3c0b9a31b9bd82b89c23c0072d8686bd61f8b833832a78144d573bc4e2919",
                "9164cbb71997b016efe7c51d2547358800ddf9f1d7b516cf7981a50dc23e4cd3641bd272b800cd1769ab2fcb54cf32eb27cdd3cbc4ad5343229de2353d20df8b",
                "6142bb79122f9dcd14de8dc28b10fa515ea059dda28204f638bcd8f4c091218e805f637cfc742f4945ff56aad0b5d1c1d1baffba33a2936ae9a832fade11479a"
                );
        }

        private void rfc2945TestVectors(
			IDigest digest, 
			string tN,
			string tg,
			string user,
			string password,
			string salt,
			string tk,
			string tx,
			string tv,
			string ta,
			string tb,
			string tA,
			string tB,
			string tu,
			string tS,
			string tK,
			string tM1,
			string tM2
			)
        {
            byte[] I = Encoding.UTF8.GetBytes(user);
            byte[] P = Encoding.UTF8.GetBytes(password);
            byte[] s = Hex.Decode(salt);
            BigInteger N = FromHex(tN);
            BigInteger g = FromHex(tg);
            BigInteger a = FromHex(ta);
            BigInteger b = FromHex(tb);

            BigInteger expect_k = FromHex(tk);
            BigInteger expect_x = FromHex(tx);
            BigInteger expect_v = FromHex(tv);
            BigInteger expect_A = FromHex(tA);
            BigInteger expect_B = FromHex(tB);
            BigInteger expect_u = FromHex(tu);
            BigInteger expect_S = FromHex(tS);
            BigInteger expect_K = FromHex(tK);
            BigInteger expect_M1 = FromHex(tM1);
            BigInteger expect_M2 = FromHex(tM2);

            BigInteger k = Srp6Utilities.CalculateK(digest, N, g);
            if (!k.Equals(expect_k))
            {
                Fail("wrong value of 'k'");
            }

            BigInteger x = Srp6Utilities.CalculateX(digest, N, s, I, P);
            if (!x.Equals(expect_x))
            {
                Fail("wrong value of 'x'");
            }

            Srp6VerifierGenerator gen = new Srp6VerifierGenerator();
            gen.Init(N, g, digest);
            BigInteger v = gen.GenerateVerifier(s, I, P);
            if (!v.Equals(expect_v))
            {
                Fail("wrong value of 'v'");
            }

            byte[] messageVerifier = gen.GenerateMessageVerifierRFC2945(s, I);

            Srp6Client client = new MySrp6Client(a);
            client.Init(N, g, digest, random);

            BigInteger A = client.GenerateClientCredentials(s, I, P);
            if (!A.Equals(expect_A))
            {
                Fail("wrong value of 'A'");
            }

            Srp6Server server = new MySrp6Server(b);
            server.Init(N, g, v, digest, random);

            BigInteger B = server.GenerateServerCredentials();
            if (!B.Equals(expect_B))
            {
                Fail("wrong value of 'B'");
            }

            BigInteger u = Srp6Utilities.CalculateU(digest, N, A, B);
            if (!u.Equals(expect_u))
            {
                Fail("wrong value of 'u'");
            }

            BigInteger clientS = client.CalculateSecret(B);
            if (!clientS.Equals(expect_S))
            {
                Fail("wrong value of 'S' (client)");
            }

            BigInteger serverS = server.CalculateSecret(A);
            if (!serverS.Equals(expect_S))
            {
                Fail("wrong value of 'S' (server)");
            }

            BigInteger clientM1 = client.CalculateClientEvidenceMessageRFC2945(messageVerifier);
            bool isClientM1Valid = server.VerifyClientEvidenceMessageRFC2945(clientM1, messageVerifier);
            if (!isClientM1Valid)
            {
                Fail("SRP server was not able to verify M1 from the client");
            }

            if (!clientM1.Equals(expect_M1))
            {
                Fail("wrong value of 'M1' (client)");
            }

            BigInteger serverM2 = server.CalculateServerEvidenceMessage();
            bool isServerM2Valid = client.VerifyServerEvidenceMessage(serverM2);
            if (!isServerM2Valid)
            {
                Fail("SRP client was not able to verify M2 from the server");
            }

			if (!serverM2.Equals(expect_M2))
			{
				Fail("wrong value of 'M2' (server)");
			}

			BigInteger sessionKey = client.CalculateSessionKey();
            if (!sessionKey.Equals(expect_K))
            {
                Fail("wrong value of 'K' (client)");
            }
        }

        private void rfc2945MessageVerify()
        {
            BigInteger N = Srp6StandardGroups.rfc5054_1024.N;
            BigInteger g = Srp6StandardGroups.rfc5054_1024.G;

            byte[] I = Encoding.UTF8.GetBytes("username");
            byte[] P = Encoding.UTF8.GetBytes("password");
            byte[] s = new byte[16];
            random.NextBytes(s);

            var group = new Srp6GroupParameters(N, g);

            Srp6VerifierGenerator gen = new Srp6VerifierGenerator();
            gen.Init(group, new Sha256Digest());
            BigInteger v = gen.GenerateVerifier(s, I, P);
            byte[] messageVerifier = gen.GenerateMessageVerifierRFC2945(s, I);

            Srp6Client client = new Srp6Client();
            client.Init(group, new Sha256Digest(), random);

            Srp6Server server = new Srp6Server();
            server.Init(group, v, new Sha256Digest(), random);

            BigInteger A = client.GenerateClientCredentials(s, I, P);
            BigInteger B = server.GenerateServerCredentials();

            BigInteger clientS = client.CalculateSecret(B);
            BigInteger clientM1 = client.CalculateClientEvidenceMessageRFC2945(messageVerifier);

            BigInteger serverS = server.CalculateSecret(A);

            if (!clientS.Equals(serverS))
            {
                Fail("SRP agreement failed - client/server calculated different secrets");
            }

            bool isClientM1Valid =  server.VerifyClientEvidenceMessageRFC2945(clientM1, messageVerifier);
            if(!isClientM1Valid)
            {
                Fail("SRP server was not able to verify M1 from the client");
            }

            BigInteger serverM2 = server.CalculateServerEvidenceMessage();
            bool isServerM2Valid = client.VerifyServerEvidenceMessage(serverM2);
            if (!isServerM2Valid)
            {
                Fail("SRP client was not able to verify M2 from the server");
            }
        }

        private void rfc5054AppendixBTestVectors()
	    {
	    	byte[] I = Encoding.UTF8.GetBytes("alice");
	    	byte[] P = Encoding.UTF8.GetBytes("password123");
	    	byte[] s = Hex.Decode("BEB25379D1A8581EB5A727673A2441EE");
            BigInteger N = Srp6StandardGroups.rfc5054_1024.N;
            BigInteger g = Srp6StandardGroups.rfc5054_1024.G;
	    	BigInteger a = FromHex("60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393");
	    	BigInteger b = FromHex("E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20");

	    	BigInteger expect_k = FromHex("7556AA045AEF2CDD07ABAF0F665C3E818913186F");
	    	BigInteger expect_x = FromHex("94B7555AABE9127CC58CCF4993DB6CF84D16C124");
	    	BigInteger expect_v = FromHex("7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D812"
	            + "9BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5"
	            + "C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5"
	            + "EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78"
	            + "E955A5E29E7AB245DB2BE315E2099AFB");
	    	BigInteger expect_A = FromHex("61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC4"
	            + "4352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC"
	            + "8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44"
	            + "BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEA"
	            + "B349EF5D76988A3672FAC47B0769447B");
	    	BigInteger expect_B = FromHex("BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011"
	            + "BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC99"
	            + "6C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA"
	            + "37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAE"
	            + "EB4012B7D7665238A8E3FB004B117B58");
	    	BigInteger expect_u = FromHex("CE38B9593487DA98554ED47D70A7AE5F462EF019");
	    	BigInteger expect_S = FromHex("B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D"
	            + "233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C"
	            + "41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F"
	            + "3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212D"
	            + "C346D7E474B29EDE8A469FFECA686E5A");

	    	BigInteger k = Srp6Utilities.CalculateK(new Sha1Digest(), N, g);
	    	if (!k.Equals(expect_k))
	    	{
	    		Fail("wrong value of 'k'");
	    	}

	    	BigInteger x = Srp6Utilities.CalculateX(new Sha1Digest(), N, s, I, P);
	    	if (!x.Equals(expect_x))
	    	{
	    		Fail("wrong value of 'x'");
	    	}

	    	Srp6VerifierGenerator gen = new Srp6VerifierGenerator();
	    	gen.Init(N, g, new Sha1Digest());
	    	BigInteger v = gen.GenerateVerifier(s, I, P);
	    	if (!v.Equals(expect_v))
	    	{
	    		Fail("wrong value of 'v'");
	    	}

	        Srp6Client client = new MySrp6Client(a);
	        client.Init(N, g, new Sha1Digest(), random);

	    	BigInteger A = client.GenerateClientCredentials(s, I, P);
	    	if (!A.Equals(expect_A))
	    	{
	    		Fail("wrong value of 'A'");
	    	}

	    	Srp6Server server = new MySrp6Server(b);
	        server.Init(N, g, v, new Sha1Digest(), random);

	    	BigInteger B = server.GenerateServerCredentials();
	    	if (!B.Equals(expect_B))
	    	{
	    		Fail("wrong value of 'B'");
	    	}

	        BigInteger u = Srp6Utilities.CalculateU(new Sha1Digest(), N, A, B);
	    	if (!u.Equals(expect_u))
	    	{
	    		Fail("wrong value of 'u'");
	    	}

	        BigInteger clientS = client.CalculateSecret(B);
	        if (!clientS.Equals(expect_S))
	    	{
	    		Fail("wrong value of 'S' (client)");
	    	}

	        BigInteger serverS = server.CalculateSecret(A);
	        if (!serverS.Equals(expect_S))
	    	{
	    		Fail("wrong value of 'S' (server)");
	    	}
	    }

		private void testWithRandomParams(int bits)
		{
	        DHParametersGenerator paramGen = new DHParametersGenerator();
	        paramGen.Init(bits, 25, random);
	        DHParameters parameters = paramGen.GenerateParameters();

            testMutualVerification(new Srp6GroupParameters(parameters.P, parameters.G));
		}

        private void testMutualVerification(Srp6GroupParameters group)
	    {
	        byte[] I = Encoding.UTF8.GetBytes("username");
	        byte[] P = Encoding.UTF8.GetBytes("password");
	        byte[] s = new byte[16];
	        random.NextBytes(s);

	        Srp6VerifierGenerator gen = new Srp6VerifierGenerator();
	        gen.Init(group, new Sha256Digest());
	        BigInteger v = gen.GenerateVerifier(s, I, P);

	        Srp6Client client = new Srp6Client();
	        client.Init(group, new Sha256Digest(), random);

	        Srp6Server server = new Srp6Server();
	        server.Init(group, v, new Sha256Digest(), random);

            BigInteger A = client.GenerateClientCredentials(s, I, P);
	        BigInteger B = server.GenerateServerCredentials();

	        BigInteger clientS = client.CalculateSecret(B);
	        BigInteger serverS = server.CalculateSecret(A);

	        if (!clientS.Equals(serverS))
	        {
	            Fail("SRP agreement failed - client/server calculated different secrets");
	        }
	    }

        private void testClientCatchesBadB(Srp6GroupParameters group)
	    {
	        byte[] I = Encoding.UTF8.GetBytes("username");
	        byte[] P = Encoding.UTF8.GetBytes("password");
	        byte[] s = new byte[16];
	        random.NextBytes(s);

	        Srp6Client client = new Srp6Client();
	        client.Init(group, new Sha256Digest(), random);

	        client.GenerateClientCredentials(s, I, P);

	        try
	        {
	        	client.CalculateSecret(BigInteger.Zero);
	        	Fail("Client failed to detect invalid value for 'B'");
	        }
	        catch (CryptoException)
	        {
	        	// Expected
	        }

	        try
	        {
	        	client.CalculateSecret(group.N);
	        	Fail("Client failed to detect invalid value for 'B'");
	        }
	        catch (CryptoException)
	        {
	        	// Expected
	        }
	    }

        private void testServerCatchesBadA(Srp6GroupParameters group)
	    {
	        byte[] I = Encoding.UTF8.GetBytes("username");
	        byte[] P = Encoding.UTF8.GetBytes("password");
	        byte[] s = new byte[16];
	        random.NextBytes(s);

	        Srp6VerifierGenerator gen = new Srp6VerifierGenerator();
	        gen.Init(group, new Sha256Digest());
	        BigInteger v = gen.GenerateVerifier(s, I, P);

	        Srp6Server server = new Srp6Server();
	        server.Init(group, v, new Sha256Digest(), random);

	        server.GenerateServerCredentials();

	        try
	        {
	        	server.CalculateSecret(BigInteger.Zero);
	        	Fail("Client failed to detect invalid value for 'A'");
	        }
	        catch (CryptoException)
	        {
	        	// Expected
	        }

	        try
	        {
	        	server.CalculateSecret(group.N);
	        	Fail("Client failed to detect invalid value for 'A'");
	        }
	        catch (CryptoException)
	        {
	        	// Expected
	        }
	    }

		[Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();
            Assert.AreEqual(Name + ": Okay", resultText);
        }

		private class MySrp6Client
			: Srp6Client
		{
			private readonly BigInteger nonRandomPrivA;

			internal MySrp6Client(BigInteger nonRandomPrivA)
			{
				this.nonRandomPrivA = nonRandomPrivA;
			}

            protected override BigInteger SelectPrivateValue()
            {
                return nonRandomPrivA;
            }
		}

		private class MySrp6Server
			: Srp6Server
		{
			private readonly BigInteger nonRandomPrivB;

			internal MySrp6Server(BigInteger nonRandomPrivB)
			{
				this.nonRandomPrivB = nonRandomPrivB;
			}

            protected override BigInteger SelectPrivateValue()
            {
                return nonRandomPrivB;
            }
		}
	}
}
