Visual Studio로 컴파일 / 빌드되었습니다.

실행을 위해서는 OpenSSL 과 Qt의 설치가 필요합니다.
OpenSSL의 경우 , vcpkg(패키지 관리 툴)를 통해 바로 설치가 가능합니다.
vcpkg 설치의 경우 다음 링크를 참고해주세요.
https://velog.io/@copyrat90/getting-started-with-vcpkg

그 뒤 VS에서 CMD를 열고
'''bash
vcpkg integrate install
'''
를 작성해주세요. OpenSSL이 자동으로 설치됩니다.

Qt의 경우, 인터넷에서 다운로드 후, 실행 경로를 지정해주셔야 합니다.
CMakePreset.json 파일에 configurePreset에 

"toolchainFile": "$env{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake",
"cacheVariables": {
  "VCPKG_TARGET_TRIPLET": "x64-windows",
  "CMAKE_PREFIX_PATH": "C:/Qt/6.9.0/msvc2022_64" #Qt 설치 경로 , msvc 버전이어야함 !!
},

를 추가해주세요

그리고 vcpkg.json 파일에 
"dependencies": [
  "openssl"
],
도 추가해주세요

깃허브 파일을 그대로 받으신다면, 딱히 위 내용을 수정할 일은 없을 것입니다만, 혹시 모르니 작성해둡니다.

이제 qt를 열고 file_compression_encryption\out\build\x64-debug\gui\Debug 주소로 이동해서
'''bash
windeployqt hufcrypt_gui.exe 
'''
명령어를 쳐줍니다._

모든 과정이 정상적으로 진행되었다면 , 성공적으로 실행됩니다.
감사합니다.
