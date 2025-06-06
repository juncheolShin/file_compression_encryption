실행을 위해서는 OpenSSL 과 Qt의 설치가 필요합니다.
OpenSSL의 경우 , vcpkg(패키지 관리 툴)를 통해 바로 설치가 가능합니다.
그러나, Qt의 경우, 인터넷에서 다운로드 후, 실행 경로를 지정해주셔야 합니다.
CMakePreset.json 파일에 configurePreset에 

"toolchainFile": "$env{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake",
"cacheVariables": {
  "VCPKG_TARGET_TRIPLET": "x64-windows",
  "CMAKE_PREFIX_PATH": "C:/Qt/6.9.0/msvc2022_64" #Qt 설치 경로 , msvc 버전이어야함 !!
},

를 추가해준다면 실행이 될 것입니다.

그리고 vcpkg.json 파일에 
"dependencies": [
  "openssl"
],
도 추가해주시면 실행이 될 것입니다.

만약 안된다면, 오류메세지 그대로 gpt 물어보면 친절하게 답 해줍니다.

감사합니다.