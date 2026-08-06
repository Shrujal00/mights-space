#!/usr/bin/env bash
# Build the mock sample APK.
#
# Run by hand, not by the test suite — the suite must stay hermetic and must not
# depend on an Android SDK being installed. The built APK is committed so that
# validating the sandbox does not require this toolchain.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
BUILD_TOOLS="$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)"
ANDROID_JAR="$(ls "$SDK"/platforms/*/android.jar | sort -V | tail -1)"
OUT="$HERE/build"

echo "build-tools: $BUILD_TOOLS"
echo "android.jar: $ANDROID_JAR"

rm -rf "$OUT"
mkdir -p "$OUT/classes"

echo "=== compiling Java ==="
javac -source 8 -target 8 -bootclasspath "$ANDROID_JAR" -classpath "$ANDROID_JAR" \
  -d "$OUT/classes" \
  $(find "$HERE/src" -name '*.java') 2>&1 | grep -v "^Note:" || true

echo "=== dexing ==="
"$BUILD_TOOLS/d8" --min-api 21 --output "$OUT" \
  $(find "$OUT/classes" -name '*.class')

echo "=== packaging manifest ==="
"$BUILD_TOOLS/aapt2" link \
  -I "$ANDROID_JAR" \
  --manifest "$HERE/AndroidManifest.xml" \
  --min-sdk-version 21 \
  --target-sdk-version 30 \
  -o "$OUT/unsigned.apk"

echo "=== adding classes.dex ==="
(cd "$OUT" && zip -q unsigned.apk classes.dex)

echo "=== signing ==="
KEYSTORE="$OUT/debug.keystore"
keytool -genkeypair -keystore "$KEYSTORE" -alias mock -storepass android \
  -keypass android -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=Mock Sample, OU=Testing, O=mights-space, C=IN" >/dev/null 2>&1

"$BUILD_TOOLS/zipalign" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
"$BUILD_TOOLS/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:android \
  --key-pass pass:android --out "$HERE/mock_sample.apk" "$OUT/aligned.apk"

rm -rf "$OUT"
echo "=== built: $HERE/mock_sample.apk ==="
ls -la "$HERE/mock_sample.apk"
