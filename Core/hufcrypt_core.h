#pragma once

#ifndef HUFCRYPT_CORE_H
#define HUFCRYPT_CORE_H

#include <string>
#include <functional>
#include <cstddef>   // size_t
#include <QObject>

namespace hufcrypt
{
    class logEmitter : public QObject {
        Q_OBJECT
    public:
        explicit logEmitter(QObject* parent = nullptr) : QObject(parent) {};
    signals:
        void logMessage(QString message);
    };
    /**
     * @param encrypt     true  = 압축+암호화,  false = 복호+해제
     * @param inPath      입력 파일 경로
     * @param outPath     출력 파일 경로
     * @param password    비밀번호
     * @param progress    진행률 콜백 (선택)  progress(doneBytes, totalBytes)
     * @return            성공 여부
     */
    bool process(bool enc,
        const std::string& inPath,
        const std::string& outPath,
        const std::string& pw,
        std::function<void(std::size_t, std::size_t)> progress = {},
        logEmitter * emitter = nullptr);
}

#endif // HUFCRYPT_CORE_H