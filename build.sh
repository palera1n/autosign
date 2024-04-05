#!/bin/sh

set -e

xcodebuild -sdk appletvos -project autosign.xcodeproj -scheme autosign -configuration Release -derivedDataPath build
xcodebuild -sdk iphoneos -project autosign.xcodeproj -scheme autosign -configuration Release -derivedDataPath build

install -m644 build/Build/Products/Release-appletvos/autosign_*_appletvos-arm64.deb .
install -m644 build/Build/Products/Release-iphoneos/autosign_*_iphoneos-arm.deb .
