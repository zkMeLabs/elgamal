import 'package:flutter_test/flutter_test.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/export.dart';
import 'package:threshold_encryption_dart/threshold_encryption_dart.dart';

void main() {
  group('ThresholdEncryption', () {
    late ThresholdEncryption key1;
    late ThresholdEncryption key2;

    late Map<String, ECPoint?> encryptMap;

    test('generate key1', () {
      // key1 = ThresholdEncryption.importPrivateKey(BigInt.parse(
      //     '20182014176007298211206927382189583298262006456911758742831072696828668707855'));

      key1 = ThresholdEncryption.generate();

      // print('key1 publicKey: ${key1.publicKey.Q}');
      // print('key1 privateKey: ${key1.privateKey.d}');
    });

    test('generate key2', () {
      // key2 = ThresholdEncryption.importPrivateKey(BigInt.parse(
      //     '76777945924606926015635359951940240731760752010864600843076982888613717648675'));

      key2 = ThresholdEncryption.generate();
      // print('key2 publicKey: ${key2.publicKey.Q}');
      // print('key2 privateKey: ${key2.privateKey.d}');
    });
    test('encrypt', () {
      var x = decodeBigIntWithSign(
          1,
          HEX.decode(
              '7c9947fc13203c566d28885ef6a6dd33b6409cee1a3f572a302a2db1a41028de'));
      var y = decodeBigIntWithSign(
          1,
          HEX.decode(
              '94fa30532d698b848a9b31697f48b863ca682406892ce706832a33b4a3c9ea99'));
      encryptMap = ThresholdEncryption.encrypt(key1, key2.publicKey.Q!, x, y);
      print(encryptMap);
    });

    test('decrypt', () {
      var c1Point = encryptMap['c1']!;
      var c2Point = encryptMap['c2']!;

      var c1 = ThresholdEncryption.fromXYtoPoint(
          c1Point.x!.toBigInteger()!, c1Point.y!.toBigInteger()!);
      var c2 = ThresholdEncryption.fromXYtoPoint(
          c2Point.x!.toBigInteger()!, c2Point.y!.toBigInteger()!);

      var yc1 = ThresholdEncryption.createPoint(
              c1Point.x!.toBigInteger()!, c1Point.y!.toBigInteger()!) *
          key2.privateKey.d;

      var vv =
          ThresholdEncryption.decrypt(key: key1, c1: c1, c2: c2, yc1: yc1!);
      print('decrypt:\n'
          'x: ${vv?.x?.toBigInteger()?.toRadixString(16)}\n'
          'y: ${vv?.y?.toBigInteger()?.toRadixString(16)}');
    });
  });
}
