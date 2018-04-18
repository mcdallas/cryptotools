import unittest
import pathlib

from btctools.transaction import Transaction, Output
from btctools.script import push, serialize
from btctools.opcodes import SIGHASH, TX
from ECDS.secp256k1 import PublicKey, PrivateKey
from message import Signature
from transformations import *


ECHO = False
HERE = pathlib.Path(__file__).parent.absolute()


def tx_path(txhash):
    return HERE / "transactions" / f"{txhash}.txt"


old_get = Transaction.get
tx_cache = {}


def get(txhash):
    if isinstance(txhash, bytes):
        txhash = bytes_to_hex(txhash)
    if txhash in tx_cache:
        if ECHO:
            print(f"\nGetting tx {txhash} from cache")
        return Transaction.from_hex(tx_cache[txhash])
    try:
        with open(tx_path(txhash)) as f:
            if ECHO:
                print(f"\nGetting tx {txhash} from file")
            hexstring = f.read()
            tx_cache[txhash] = hexstring
            return Transaction.from_hex(hexstring)
    except FileNotFoundError:
        if ECHO:
            print(f"\nGetting tx {txhash} from blockchain.info")
        tx = old_get(txhash)
        tx_cache[txhash] = tx.hex()
        return tx


Transaction.get = get


class TestTransaction(unittest.TestCase):

    def test_deserialize(self):
        # https://bchain.info/BTC/tx/96534da2f213367a6d589f18d7d6d1689748cd911f8c33a9aee754a80de166be
        tx = hex_to_bytes(
            '01000000'  # version
            '01'  # input count
            '75db462b20dd144dd143f5314270569c0a61191f1378c164ce4262e9bff1b079'  # previous output hash
            '00000000'  # previous output index
            '8b'  # script length
            '4830450221008f906b9fe728cb17c81deccd6704f664ed1ac920223bb2eca918f066269c703302203b1c496fd4c3fa5071262b98447fbca5e3ed7a52efe3da26aa58f738bd342d31014104bca69c59dc7a6d8ef4d3043bdcb626e9e29837b9beb143168938ae8165848bfc788d6ff4cdf1ef843e6a9ccda988b323d12a367dd758261dd27a63f18f56ce77'  # scriptSig
            'ffffffff'  # sequence
            '01'  # output count
            '33f5010000000000'  # value (in satoshis)
            '19'  # script length
            '76a914dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac'  # scriptPubKey  
            '00000000'  # lock time
        )

        trans = Transaction.deserialize(tx)
        self.assertEqual(len(trans.inputs), 1)
        self.assertEqual(len(trans.outputs), 1)
        self.assertEqual(trans.json()['txid'], '96534da2f213367a6d589f18d7d6d1689748cd911f8c33a9aee754a80de166be')
        self.assertEqual(trans.serialize(), tx)

        tx = '0100000018c24951446d11d904acdb5131e944e1466fcd4cf830b9cd5f128816c94ba5ce81000000006a473044022' \
             '041b174db2f7c0105cda6063aa28b2652718c754c04e0bfb5258cb7146de2132202205a118dbd6e87a0f11199c7e2' \
             '533b9dcc54eeec0c793dcb27e8b920d6fa89abe60121020def33984ae5443ebedd3e11081507a549272509823598c' \
             'aee46557157e75c7bffffffff25c68048091d87b6cec786caeb1278efadfd697b736bb4e026c9f27c504968420200' \
             '00006a473044022023b053e82198bea624eee4f1286877b814d7706fc7aa3c90aea172c7a11c37e9022005b139f3e' \
             '3033293b6501f89791d29a58fb92ced7edf4821a3a4c5e13f8ab252012102f745e53a8bdce547300003d9af8534b8' \
             '9f49cc6e9f946ec0cf42e3594dd5bf04ffffffffb24cc36140b7a996d3ad7585483b0f5f1b7bef9a1dacf03925649' \
             '336b5731c22020000006a47304402200561512b14a65099a9f7eb991f7bdff96e0f1a64d1c94d45216a9274d6d2d4' \
             'e3022008605d39aed3682488b5e145b647d842c3ac5f1b2663a038de2e0173f17e43b2012102f745e53a8bdce5473' \
             '00003d9af8534b89f49cc6e9f946ec0cf42e3594dd5bf04ffffffffc83af1d8965cd7c3b8d6702e21842987e2db08' \
             'f0855ca231531ecde5841e888d090000006b483045022100991c5b24a7b826db45fc7cc74eacfa0caafd074a743b6' \
             'bab6be2a8b85697ccee022031bacd966577fdbc346e69038bc032ea371c2290edfb6e94f8752633ccff6832012102' \
             'ba1573908263358b61bc92c136a0dc0ec740323f7838ba7c3a8d4ee267bc5ed0fffffffff7f5701e6d767e75c5a1b' \
             'b34f3488a93ad043f38f65154edfed7c6a4e9f6748fe20000006b483045022100873699205ffc2255b484f7c953d2' \
             '2a9f21a5f55640473384310e747699d3767202203728e52c212182739ea96c60524b9f355a269c9e0b2abe49f2330' \
             '6c8e1e4086f0121032d6bf528e3aeda4bb95c72add0eb2e485515c567611766179402471ddc529582fffffffff7f5' \
             '701e6d767e75c5a1bb34f3488a93ad043f38f65154edfed7c6a4e9f6748f710000006b48304502210098b501b208a' \
             '9b3218c59b86d597d51ab0c0e6173d33924fc186081fc8c5e05b7022064abba92beb9672bdc8c698260b901845ff8' \
             '438760fbe8d01caadd272c4787720121021907b8f6af43e418782c3498ab9b1c0658073d20dcb153c229e453b24c3' \
             '98fa3ffffffff49dd6ede00b4252d3276a3ac1ade300ef4fa4dd68d8c4998f8eb89c52137b78b000000006b483045' \
             '02210084c65f3157661176452df24ad68953154fdda42d72ddfc2b08a3fe330a2f89710220393ec7485a54eab3263' \
             '319402f4f9e5ecdef9f189272c346b687144b28ec446c012102bf20453dcc535a1b73e2452bb250dd7b9e0437e3ab' \
             'be34fd54091de6eefe1986fffffffff7f5701e6d767e75c5a1bb34f3488a93ad043f38f65154edfed7c6a4e9f6748' \
             'fea0000006a4730440220472abc9b71ae5f746060669c89a3d756042a9813fa600f7975d90cd8a6162e5c0220742a' \
             'fd69c8eb7a5d3ee8aa8f99874a971080f7e9ecef20763babeebc53115bc60121026deb06ff54c3a33760a2a874122' \
             '5a6874413685f2b02611b22308c6575a24ae6fffffffff7f5701e6d767e75c5a1bb34f3488a93ad043f38f65154ed' \
             'fed7c6a4e9f6748fa50000006b483045022100dd5526023cf29d406b4b49a96d90b7abd4b6c3083629ff328497722' \
             '6f22d749a0220177c1333a780e49c8de37d736f3aca1b30156bcd04f841b8c696a9111356b427012103bc9bea296e' \
             'f8ca3f794d961fd6a87ab158245b0402b174ceccf1a57a68233d4affffffff24e7c48974feda2696e0603c720ffd9' \
             'c8643156d392fda74c68937faebef4642560400006b483045022100d39c7af74278e939f4d66fdabadc1eb0d9e015' \
             '33d35d325b7a6060cc981c0a8302203c32e1f398a9c69948472ec55f26ed995f50cb17868685249546c7d09671959' \
             '1012102916244a6b8fc168aa51a41ba1139920b234b2dccd0b945a47d28bf8aa19f8bcdffffffff24e7c48974feda' \
             '2696e0603c720ffd9c8643156d392fda74c68937faebef4642520600006a47304402203d1a5f4bba7905e9713a6cf' \
             '8d9a5e9fc98c22b3e7895c1fe0aba09ebb20c5e310220796050be432c9afbf383bb3efde520da2ce46eb62bbe2c80' \
             '0b40f96e8bb61052012102f834c88f6c10766a57b0562b085ad452514e20d2b9d583ac97149a2b648bca26fffffff' \
             'f24e7c48974feda2696e0603c720ffd9c8643156d392fda74c68937faebef4642d30600006b483045022100ea551a' \
             '2b86684df1c1d57b3c6f21c248a9e5aade1167709999de1559239e76d602203a729429f856f7d6b044f67faad02a1' \
             '0db76e0e8fd14bfb0c002910bab4091a90121029ccbfe48fdcd7e93694eb5f0eeaecdc0f6085605c5f28b6e2e3415' \
             '8292c1fe11ffffffff24e7c48974feda2696e0603c720ffd9c8643156d392fda74c68937faebef46425e0400006a4' \
             '7304402201049f59241600a3880da0d762bce3ab6b73cb58b707684e56baa7bef9384adcd0220589749b4e93dce88' \
             '10bcd57e26fd7f9ed91c00ad48641aa5cc0d2979caad937a01210232d152b7df3aa531c609425b949009244e1a1d8' \
             'c2970905e672772d72c5b1033ffffffff24e7c48974feda2696e0603c720ffd9c8643156d392fda74c68937faebef' \
             '46425f0400006a473044022014dd7c39479ce7ab55654992e9eefa7ef965a32305559243f87d6552d0afe3bb02203' \
             '9c1e119866faa0b14ac31c93af6674cded2f32612c2321b31caf8e2a5e45f4f012102d998c9108295bee5fa6aec14' \
             'bc5ff96a45dca7200c778d09cdd6494c46a53c51ffffffff24e7c48974feda2696e0603c720ffd9c8643156d392fd' \
             'a74c68937faebef4642600400006a47304402207dff5e098ad2997eb52da0709ed9afde5604d6138ee3e7b1fdb2b5' \
             'fdbe9f1d23022036504c6038c0ed9dbad7c6a0ef34085c501cb578d82ab148f1903dc2ad21ad3d012102312c98d36' \
             '96ad96668eddff4a1d8cb447f312310acd4b371e8100258f9d362c2ffffffff24e7c48974feda2696e0603c720ffd' \
             '9c8643156d392fda74c68937faebef4642620400006a473044022037f86eb0a1fd225d191920de410e88b4a03b843' \
             '849bb7fc302fa003ffb0549c8022010ed8260442685a365a90782f157145be6b440f42ed18bffa718d5a8f27dbfd6' \
             '01210290173c896bad9acbbf9db5f4d1872746d713f0afe955a6caba93c8497ea3cb6affffffff24e7c48974feda2' \
             '696e0603c720ffd9c8643156d392fda74c68937faebef46426c0400006b483045022100a6638e75ed23e1ccd925ef' \
             '20ffab6b525afe22516de24653b36eb5d576d69b59022027d109242cf2759c1f2acaa0e33d4582b74dbcdcdb772a5' \
             '3392af1f15004dcf9012102fc6c2b1d04314812c5051e42dbf387638333705b83a504be226c9ac60da42dd8ffffff' \
             'ff24e7c48974feda2696e0603c720ffd9c8643156d392fda74c68937faebef46426d0400006a47304402200b22dcc' \
             '618a112b5737e2e9e3849f0f0635f6870082f6b53601ada58447eb40602204b4a2aecccfdb105871c4b8a32df1ce0' \
             'd18674f004720d2f5c1f59aa0353f0d3012102b4b1b917efd04b983ed961c7827a152008383699ba45f515514d83f' \
             '2cd5cb18cffffffff24e7c48974feda2696e0603c720ffd9c8643156d392fda74c68937faebef46426e0400006a47' \
             '304402203ca6b80f0265e2fa2c76420abe5b7c2b09c3ee8844168bd299018fea02f09197022055ebe7230d6374bf5' \
             '614ee52b3ef943086af1eefff696301778b5a57a367c929012102863d026ad83c71b2e257e8800cdd59e54c36cea2' \
             '3b5ab42db3edee26d7b3de3affffffff24e7c48974feda2696e0603c720ffd9c8643156d392fda74c68937faebef4' \
             '642760400006a4730440220247f6f3c94ca9f0cf3b9328826e6cc17eae8970c15ec773883dd4f2a806a9908022069' \
             '57c20b67549e9beefcafba83d9bd947d93feb2b11a056684bb5e01870527ca012102027128694d4518239d862638a' \
             'aca3289b4e03f527939c123663cb89ffa913bd7ffffffff24e7c48974feda2696e0603c720ffd9c8643156d392fda' \
             '74c68937faebef4642fa0500006b483045022100c4d4fb895932882f7effa69eb87ca5d7f18cc4779846dc5394776' \
             '7c008b5f3cf02200f9f920e76c95314d0ef563672b45d13f0595196576f08060ee5c7e15c131038012102e266b556' \
             'da0e691913f57299eb17afa663db313a412ae8604d6e3168b5016427ffffffff24e7c48974feda2696e0603c720ff' \
             'd9c8643156d392fda74c68937faebef46427a0400006a47304402203d727ffc923327dc44b90efc6518961f262c4f' \
             '2936a012c4cec8d1f5bf3285e5022073d01eac511ec9463ac321c8570dba10175e27471e235b9a71c92b8befa8af4' \
             '50121025d9a75f4a292c029efe7829654e2576bb0e6a95e453f474969dc60a346345f89ffffffff24e7c48974feda' \
             '2696e0603c720ffd9c8643156d392fda74c68937faebef46429a0600006b483045022100f688e12ebd1b7d3d0780a' \
             'cd40294609c4b4a537940ba11fe5d7e45f95baa30a602200bc78f656bb4ad18bbffe2e3d5dbac292786bdd520517b' \
             '336a45735ea6ce2a7d01210248253858582ca9ff6e6a36d8737a744a467de29dee1e90598c89af68ad069a75fffff' \
             'fff24e7c48974feda2696e0603c720ffd9c8643156d392fda74c68937faebef4642810400006a4730440220490a28' \
             'ca75c9835c828c0b4f812efc67ad3a82b3b4a85e35a3ebb2d0a018b66302203ff4d2f89c81256a02be48ce7119b7c' \
             'eee8d2942ba589a6ebaee677a6282ea490121034465d66cafc2047298744c6c838551ad35bdb1498f4421722a7395' \
             '2c8ab2d3ffffffffff0700273800000000001976a9142403d3630b8d56b2dee74ca86c14b1aa2c0dee4988ac002d3' \
             '101000000001976a914a381b84bb4d6e2a9e335aa904714337a015f82c988ac66896c00000000001976a9146310f6' \
             'c2002996969e82e48234fde42d5b5e22aa88ace8f61600000000001976a914478f73a92472981a11f9dffdc9455a7' \
             '6ddbc0ac788acc9290500000000001976a9148700ef64e9f3d737173718bfe220a0dc47dad25988ace01b18000000' \
             '000017a91459e170de61fb1ff9a607af599ed40c93cc30012a8729d7350c000000001976a914e6e87b998504818b7' \
             '55880d2fb5e5a8faf83968f88ac00000000'

        trans = Transaction.from_hex(tx)
        self.assertEqual(len(trans.inputs), 24)
        self.assertEqual(len(trans.outputs), 7)
        self.assertEqual(trans.json()['txid'], 'ef27d32f7f0c645daec3071c203399783555d84cfe92bfe61583a464a260df0b')
        self.assertEqual(trans.hex(), tx)

    def test_serialize(self):

        tx_ids = [
            '4246efebfa3789c674da2f396d1543869cfd0f723c60e09626dafe7489c4e724',
            'e5c95e9b3c8e81bf9fc4da9f069e5c40fa38cdcc0067b5706b517878298a6f7f',
            'ef27d32f7f0c645daec3071c203399783555d84cfe92bfe61583a464a260df0b'
        ]

        for tx_id in tx_ids:
            with open(tx_path(tx_id)) as f:
                tx = f.read()

            trans = Transaction.from_hex(tx)
            self.assertEqual(trans.hex(), tx)

    def test_verification(self):
        tx_ids = [
            'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16',
            '12b5633bad1f9c167d523ad1aa1947b2732a865bf5414eab2f9e5ae5d5c191ba',  # P2PK
            # 'a38d3393a32d06fe842b35ebd68aa2b6a1ccbabbbc244f67462a10fd8c81dba5',  # coinbase
            'a8d60051745755be5b13ba3ecedc1540fbb66e95ab15e76b4d871fd7c2b68794',  # segwit
            'fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4',
            'ee475443f1fbfff84ffba43ba092a70d291df233bd1428f3d09f7bd1a6054a1f',
            '5a0ce1166ff8e6800416b1aa25f1577e233f230bd21204a6505fa6ee5a9c5fc6',
            'ef27d32f7f0c645daec3071c203399783555d84cfe92bfe61583a464a260df0b',  # 24 inputs 7 outputs
            '454e575aa1ed4427985a9732d753b37dc711675eb7c977637b1eea7f600ed214',  # sends to P2SH and P2WSH
            'eba5e1e668e0d47dc28c7fff686a7f680e334e1f9740fd90f0aed3d5e9c4114a',  # spends P2WSH
            'e5c95e9b3c8e81bf9fc4da9f069e5c40fa38cdcc0067b5706b517878298a6f7f',  # non standard sequence
            'e694da982e1a725e3524c622932f6159a328194a9201588783393c35ac852732'  # P2SH-P2WSH
        ]

        for tx_id in tx_ids:
            tx = Transaction.get(tx_id)
            self.assertTrue(tx.verify())
            for inp in tx.inputs:
                self.assertTrue(inp.is_signed())

    def test_signing(self):
        tx_ids = [
            'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16',
            '12b5633bad1f9c167d523ad1aa1947b2732a865bf5414eab2f9e5ae5d5c191ba',  # P2PK
            # 'a38d3393a32d06fe842b35ebd68aa2b6a1ccbabbbc244f67462a10fd8c81dba5',  # coinbase
            'a8d60051745755be5b13ba3ecedc1540fbb66e95ab15e76b4d871fd7c2b68794',  # segwit
            'fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4',
            'ee475443f1fbfff84ffba43ba092a70d291df233bd1428f3d09f7bd1a6054a1f',
            '5a0ce1166ff8e6800416b1aa25f1577e233f230bd21204a6505fa6ee5a9c5fc6',
            'ef27d32f7f0c645daec3071c203399783555d84cfe92bfe61583a464a260df0b',  # 24 inputs 7 outputs
            '454e575aa1ed4427985a9732d753b37dc711675eb7c977637b1eea7f600ed214',  # sends to P2SH and P2WSH
            'eba5e1e668e0d47dc28c7fff686a7f680e334e1f9740fd90f0aed3d5e9c4114a',  # spends P2WSH
            'e5c95e9b3c8e81bf9fc4da9f069e5c40fa38cdcc0067b5706b517878298a6f7f',  # non standard sequence
            'e694da982e1a725e3524c622932f6159a328194a9201588783393c35ac852732'  # P2SH-P2WSH
        ]

        private = PrivateKey.random()

        for tx_id in tx_ids:
            tx = Transaction.get(tx_id)
            for inp in tx.inputs:
                if inp.ref().type() not in (TX.P2WSH, TX.P2SH):
                    self.assertTrue(inp.is_signed())
                    inp.clear()
                    self.assertFalse(inp.is_signed())
                    inp.sign(private)
                    self.assertTrue(inp.is_signed())
                    self.assertFalse(tx.verify(inp.tx_index))

    def test_deserialize_p2wpkh(self):
        """https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#Example"""
        # https://bitcoincore.org/en/segwit_wallet_dev/#basic-segregated-witness-support
        # https://bitcoin.stackexchange.com/questions/68413/how-do-i-determine-whether-an-input-or-output-is-segwit
        tx = '02000000000103628147519f94dd758b512b4737d74c8cacc5fb5222f7d83c11b6' \
             '145e58fd29e82800000017160014124646d4c8496ee6b2b34ab5c04bf4126f3d27' \
             'b0ffffffff38194499595ad826eab0ab74883f32e48e085ea9b10e13618b92785e' \
             '7da47c89020000001716001456edce5ebe8f12cc8dcc848c822af507a50fc10dff' \
             'ffffff421e873292c59d5bbb094319bb57d346892b51047c398ddf5c7820ea24bb' \
             'b661010000006a4730440220658585d7341c9aefdc2edcac20cd183e21336864b7' \
             'bc1305854dac90527e53ed0220120eb83343412a4349ce6f2b155f8b06da8ae803' \
             '075671c1329f073febfc0305012103d7c4973e0625ac76f05defcd58c08654e35f' \
             '243dfffd5255b02e29336f325f85ffffffff0319790e000000000017a914bbc85a' \
             '4bfb82a4a1771cd2b22b791d9a3a61c30187a10a96010000000017a914b54005f7' \
             '9f8aed523064395ef8221e933167f935874d5530000000000017a914555a61fc0a' \
             '4d3677d4c4868fafff723a144c9a1487024730440220629a1afef02a3c9c7e9988' \
             '557b847759b6937f60740fc3ed11fa21601f9be4fa02200ad54d20172bea8dfa16' \
             'dc8ebc7fcd49ebbddc1b3b8da189bfdc0e02022be753012102dc31388cc2fe58ec' \
             'dbbc57c3c8c8b28a8797b2aeb6ac235c6ea654223f661e5102483045022100ae8a' \
             'e6707a3701625e89ee4fcdc53f7d512509f2cc4d89cf42f1ce74ac8d8a5e02206c' \
             '20b58e4eebc4105f497d9cf95537afe03c75c461f1dd6935728278194bc8f30121' \
             '037e4c93a8f7f48647af7c6c0651714516f4ff4d991e40f5cb9a76d150460a7c4a' \
             '0000000000'

        txid = 'a8d60051745755be5b13ba3ecedc1540fbb66e95ab15e76b4d871fd7c2b68794'

        trans = Transaction.from_hex(tx)
        self.assertEqual(len(trans.inputs), 3)
        self.assertEqual(len(trans.outputs), 3)
        self.assertEqual(trans.hex(), tx)
        self.assertEqual(trans.json()['txid'], txid)
        self.assertEqual(trans.json()['size'], 599)
        i1, i2, i3 = trans.inputs
        self.assertEqual(i1.json()['witness'], [
                "30440220629a1afef02a3c9c7e9988557b847759b6937f60740fc3ed11fa21601f9be4fa02200ad54d20172bea8dfa16dc8ebc7fcd49ebbddc1b3b8da189bfdc0e02022be75301",
                "02dc31388cc2fe58ecdbbc57c3c8c8b28a8797b2aeb6ac235c6ea654223f661e51"
            ])
        self.assertEqual(i1.json()['scriptSig']['hex'], "160014124646d4c8496ee6b2b34ab5c04bf4126f3d27b0")
        self.assertEqual(i2.json()['witness'], [
                "3045022100ae8ae6707a3701625e89ee4fcdc53f7d512509f2cc4d89cf42f1ce74ac8d8a5e02206c20b58e4eebc4105f497d9cf95537afe03c75c461f1dd6935728278194bc8f301",
                "037e4c93a8f7f48647af7c6c0651714516f4ff4d991e40f5cb9a76d150460a7c4a"
            ])
        self.assertEqual(i2.sequence, 4294967295)
        o1, o2, o3 = trans.outputs
        self.assertEqual(o1.json()['scriptPubKey']['hex'], "a914bbc85a4bfb82a4a1771cd2b22b791d9a3a61c30187")
        self.assertEqual(o2.value, 0.26610337 * 10**8)

    def test_digest_p2wpkh(self):
        # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wpkh
        tx = Transaction.from_hex('0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000')
        ref = Output(6 * 10 ** 8, hex_to_bytes('00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1'))

        tx.inputs[1]._referenced_output = ref

        sighash = sha256(sha256(tx.signature_form_segwit(1)))

        self.assertEqual(bytes_to_hex(sighash), 'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670')
        public = PublicKey.from_hex('025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357')

        sig = Signature.from_hex('304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee')
        self.assertTrue(sig.verify_hash(sighash, public))

    def test_digest_p2sh_p2wpkh(self):
        # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
        tx = Transaction.from_hex('0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000')
        ref = Output(10 * 10**8, hex_to_bytes('a9144733f37cf4db86fbc2efed2500b4f4e49f31202387'))

        inp = tx.inputs[0]
        inp._referenced_output = ref
        inp.script = serialize(hex_to_bytes('001479091972186c449eb1ded22b78e40d009bdf0089'))

        sighash = tx.sighash(0)
        self.assertEqual(bytes_to_hex(sighash), '64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6')
        sig = Signature.from_hex('3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb')
        pub = PublicKey.from_hex('03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873')

        self.assertTrue(sig.verify_hash(sighash, pub))

    def test_digest_p2sh_p2wsh(self):
        # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wsh
        tx = Transaction.from_hex('010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000')
        ref = Output(int(9.87654321 * 10**8), hex_to_bytes('a9149993a429037b5d912407a71c252019287b8d27a587'))

        inp = tx.inputs[0]
        inp._referenced_output = ref
        inp.script = push(hex_to_bytes('0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54'))
        inp.witness = [hex_to_bytes('56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae')]

        sighash = tx.sighash(0, hashcode=SIGHASH.ALL)
        self.assertEqual(bytes_to_hex(sighash), '185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c')

        sighash = tx.sighash(0, SIGHASH.NONE)
        self.assertEqual(bytes_to_hex(sighash), 'e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36')

        sighash = tx.sighash(0, SIGHASH.SINGLE)
        self.assertEqual(bytes_to_hex(sighash), '1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea')

        sighash = tx.sighash(0, SIGHASH.ALL_ANYONECANPAY)
        self.assertEqual(bytes_to_hex(sighash), '2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e')

        sighash = tx.sighash(0, SIGHASH.NONE_ANYONECANPAY)
        self.assertEqual(bytes_to_hex(sighash), '781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a')

        sighash = tx.sighash(0, SIGHASH.SINGLE_ANYONECANPAY)
        self.assertEqual(bytes_to_hex(sighash), '511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b')

    def test_verify_p2wpkh(self):
        # http://n.bitcoin.ninja/checktx?txid=d869f854e1f8788bcff294cc83b280942a8c728de71eb709a2c29d10bfe21b7c
        tx = Transaction.from_hex('0100000000010115e180dc28a2327e687facc33f10f2a20da717e5548406f7ae8b4c811072f8560100000000ffffffff0100b4f505000000001976a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac02483045022100df7b7e5cda14ddf91290e02ea10786e03eb11ee36ec02dd862fe9a326bbcb7fd02203f5b4496b667e6e281cc654a2da9e4f08660c620a1051337fa8965f727eb19190121038262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990ac00000000')
        # http://n.bitcoin.ninja/checktx?txid=56f87210814c8baef7068454e517a70da2f2103fc3ac7f687e32a228dc80e115
        ref = Transaction.from_hex('0100000001b0ac96e3731db370c5ca83bad90a427d1687b65bc89fa2aef2ceeb567511e59f000000006a473044022021483045c74332e0cdf2ba3c46a7ed2abdfd7a04cd3eef79238e394a9285c8c00220536adca2c48231fa8be7fa0a24e75b0f8ecced44967652e89dd19f7fd03617a70121038262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990acffffffff05a8f8c223000000001976a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac00e1f505000000001600141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92800e1f5050000000022002001d5d92effa6ffba3efa379f9830d0f75618b13393827152d26e4309000e88b100e1f5050000000017a914901c8694c03fafd5522810e0330f26e67a8533cd8700e1f5050000000017a91485b9ff0dcb34cf513d6412c6cf4d76d9dc2401378700000000')

        tx.inputs[0]._referenced_tx = ref
        self.assertTrue(tx.verify())

    def test_verify_p2wsh(self):
        # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
        tx = Transaction.from_hex('0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000')
        # assert tx.verify()


def diff(a, b):
    for idx, (i, j) in enumerate(zip(a, b)):
        if i != j:
            print(f"diff at index {idx}: {i} vs {j}")
            break

