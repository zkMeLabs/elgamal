import 'dart:math';
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:pointycastle/export.dart';

export 'package:pointycastle/export.dart' show ECPrivateKey, ECPublicKey;

class ThresholdEncryption {
  //curve
  static final ecCurve = ECCurve_secp256r1();

  ThresholdEncryption(this.privateKey, this.publicKey);

  final ECPrivateKey privateKey;
  final ECPublicKey publicKey;

  factory ThresholdEncryption.generate() {
    //ParametersWithRandom extends CipherParameters
    final params = ParametersWithRandom(
        ECKeyGeneratorParameters(ecCurve), getSecureRandom());
    final keyGenerator = ECKeyGenerator();
    keyGenerator.init(params);
    final keypair = keyGenerator.generateKeyPair();
    final ecPrivateKey = keypair.privateKey as ECPrivateKey;
    final ecPublicKey = keypair.publicKey as ECPublicKey;
    return ThresholdEncryption(ecPrivateKey, ecPublicKey);
  }

  factory ThresholdEncryption.importPrivateKey(BigInt privateKey) {
    final ecPrivateKey = ECPrivateKey(privateKey, ecCurve);
    final ecPublicKey = ECPublicKey(ecCurve.G * ecPrivateKey.d, ecCurve);
    return ThresholdEncryption(ecPrivateKey, ecPublicKey);
  }

  static ECPoint fromXYtoPoint(BigInt x, BigInt y) =>
      ecCurve.curve.createPoint(x, y);

  static ECPoint createPoint(BigInt x, BigInt y) =>
      ecCurve.curve.createPoint(x, y);

  // encryption
  // decrypt

  static ECPoint? decrypt(
      {required ThresholdEncryption key,
      required ECPoint c1,
      required ECPoint c2,
      required ECPoint yc1}) {
    var yc2 = c1 * (key.privateKey.d);
    var yc12 = (yc1 + yc2);
    return c2 + (-yc12!);
  }

  static Map<String, ECPoint?> encrypt(
      ThresholdEncryption key1, ECPoint key2Point, BigInt x, BigInt y) {
    var point = createPoint(x, y);

    var ecPoint = add(key1.publicKey, key2Point);

    //ECCurve_secp256r1.n
    var sn = decodeBigIntWithSign(
        1,
        HEX.decode(
            'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'));
    var rd = sn - BigInt.from(10);

    var c1 = key1.publicKey.parameters!.G * rd;
    var kq = ecPoint! * rd;
    var c2 = point + kq;
    return {
      'c1': c1,
      'c2': c2,
    };
  }

  static ECPoint? add(ECPublicKey publicKey, ECPoint point) =>
      publicKey.Q! + point;
}

SecureRandom getSecureRandom() {
  final secureRandom = FortunaRandom();
  final random = Random.secure();
  final seeds = Iterable.generate(32, (_) => random.nextInt(255)).toList();
  secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
  return secureRandom;
}

/// Decode a big integer with arbitrary sign.
/// When:
/// sign == 0: Zero regardless of magnitude
/// sign < 0: Negative
/// sign > 0: Positive
BigInt decodeBigIntWithSign(int sign, List<int> magnitude) {
  if (sign == 0) {
    return BigInt.zero;
  }

  BigInt result;

  if (magnitude.length == 1) {
    result = BigInt.from(magnitude[0]);
  } else {
    result = BigInt.from(0);
    for (var i = 0; i < magnitude.length; i++) {
      var item = magnitude[magnitude.length - i - 1];
      result |= (BigInt.from(item) << (8 * i));
    }
  }

  if (result != BigInt.zero) {
    if (sign < 0) {
      result = result.toSigned(result.bitLength);
    } else {
      result = result.toUnsigned(result.bitLength);
    }
  }
  return result;
}
