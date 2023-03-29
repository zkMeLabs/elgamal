# Threshold Encryption

## generate
``` dart
ThresholdEncryption.generate();
```

## importPrivateKey
``` dart
ThresholdEncryption.importPrivateKey(BigInt.parse('76777945924606926015635359951940240731760752010864600843076982888613717648675'));
```

## encrypt
``` dart
var x = decodeBigIntWithSign(1,HEX.decode('7c9947fc13203c566d28885ef6a633b6409cee1a3f572a302a2db1a418de'));
var y = decodeBigIntWithSign(1,HEX.decode('94fa30532d698b848a9b31697f4863ca682406892ce706832a33b4a3ca99'));
var encryptMap = ThresholdEncryptioencrypt(key1,key2.publicKey.Q!, x, y);
```

## decrypt
``` dart
var c1Point = encryptMap['c1']!;
var c2Point = encryptMap['c2']!;
var c1 = ThresholdEncryption.fromXYtoPoint(c1Point.x!.toBigInteger()!, c1Point.y!.toBigInteger()!);
var c2 = ThresholdEncryption.fromXYtoPoint(c2Point.x!.toBigInteger()!, c2Point.y!.toBigInteger()!);
var yc1 = ThresholdEncryption.createPoint(c1Point.x!.toBigInteger()!, c1Point.y!.toBigInteger()!) * key2.privateKey.d;
var vv =ThresholdEncryption.decrypt(key: key1, c1: c1, c2: c2, yc1: yc1!);
print('decrypt:\n'
    'x: ${vv?.x?.toBigInteger()?.toRadixString(16)}\n'
    'y: ${vv?.y?.toBigInteger()?.toRadixString(16)}');
```